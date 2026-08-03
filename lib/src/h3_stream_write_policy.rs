//! Pure policy for H3 stream body/write-FIN lifecycle.
//!
//! Goal: never produce connection-wide FINAL_SIZE_ERROR by racing body after FIN,
//! double-FIN, or write-FIN after peer STOP_SENDING.
//!
//! These helpers are unit-tested and used by [`crate::quic_multiplexer`].

/// Whether a body write may call H3 `send_body(..., fin=false)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyWriteGate {
    /// Proceed with H3 body write under H3+QUIC locks.
    Allow,
    /// Local write side is finished, FIN in flight, or peer STOP_SENDING —
    /// do not append body (FINAL_SIZE risk). Caller should surface BrokenPipe.
    RefuseClosed,
}

/// Whether `try_h3_write_fin` may call H3 `send_body([], true)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteFinGate {
    /// Already finished (including after peer STOP_SENDING) — no-op.
    Skip,
    /// Attempt H3 write-FIN (or defer on flow control).
    Attempt,
}

/// How to treat an H3 body-write error for stream lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyWriteErrorAction {
    /// Capacity — retry later; stream still open.
    RetryLater,
    /// Peer stop / local already finished / transport final-size: retire write side;
    /// **do not** issue empty write-FIN afterward. Surface error to upper layers.
    RetireNoFurtherFin {
        /// Peer sent STOP_SENDING (cancel); not a local double-FIN bug.
        peer_stop_sending: bool,
    },
    /// Unexpected — surface to caller as hard error.
    Fatal,
}

/// Gate body write given local FIN state.
///
/// Flags must be re-checked under the same H3+QUIC locks that protect `send_body`.
pub fn gate_body_write(fin_pending: bool, fin_done: bool, peer_stopped: bool) -> BodyWriteGate {
    if fin_pending || fin_done || peer_stopped {
        BodyWriteGate::RefuseClosed
    } else {
        BodyWriteGate::Allow
    }
}

/// Gate write-FIN. After peer STOP_SENDING we never emit empty DATA+FIN.
pub fn gate_write_fin(fin_done: bool, peer_stopped: bool) -> WriteFinGate {
    if fin_done || peer_stopped {
        WriteFinGate::Skip
    } else {
        WriteFinGate::Attempt
    }
}

/// Classify quiche/H3 body errors that the multiplexer maps into lifecycle actions.
pub fn classify_body_write_error(
    stream_blocked_or_done: bool,
    peer_stop_sending: bool,
    final_size: bool,
    invalid_stream_state: bool,
    frame_unexpected: bool,
) -> BodyWriteErrorAction {
    if stream_blocked_or_done {
        return BodyWriteErrorAction::RetryLater;
    }
    if peer_stop_sending || final_size || invalid_stream_state || frame_unexpected {
        return BodyWriteErrorAction::RetireNoFurtherFin { peer_stop_sending };
    }
    BodyWriteErrorAction::Fatal
}

/// Whether a refuse-closed body write is a permanent hard error for upper layers.
pub fn refuse_closed_is_hard_error(fin_pending: bool, fin_done: bool, peer_stopped: bool) -> bool {
    // All refuse cases are permanent for this stream write side (FIN in flight means
    // no more body; done/stopped means closed).
    matches!(
        gate_body_write(fin_pending, fin_done, peer_stopped),
        BodyWriteGate::RefuseClosed
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_refused_after_fin_pending_or_done_or_peer_stop() {
        assert_eq!(gate_body_write(false, false, false), BodyWriteGate::Allow);
        assert_eq!(
            gate_body_write(true, false, false),
            BodyWriteGate::RefuseClosed
        );
        assert_eq!(
            gate_body_write(false, true, false),
            BodyWriteGate::RefuseClosed
        );
        assert_eq!(
            gate_body_write(false, false, true),
            BodyWriteGate::RefuseClosed
        );
        assert!(refuse_closed_is_hard_error(true, false, false));
        assert!(refuse_closed_is_hard_error(false, true, false));
        assert!(refuse_closed_is_hard_error(false, false, true));
        assert!(!refuse_closed_is_hard_error(false, false, false));
    }

    #[test]
    fn write_fin_skipped_after_done_or_peer_stop() {
        assert_eq!(gate_write_fin(false, false), WriteFinGate::Attempt);
        assert_eq!(gate_write_fin(true, false), WriteFinGate::Skip);
        assert_eq!(gate_write_fin(false, true), WriteFinGate::Skip);
        assert_eq!(gate_write_fin(true, true), WriteFinGate::Skip);
    }

    #[test]
    fn body_errors_retire_without_further_fin() {
        assert_eq!(
            classify_body_write_error(true, false, false, false, false),
            BodyWriteErrorAction::RetryLater
        );
        assert_eq!(
            classify_body_write_error(false, true, false, false, false),
            BodyWriteErrorAction::RetireNoFurtherFin {
                peer_stop_sending: true
            }
        );
        assert_eq!(
            classify_body_write_error(false, false, true, false, false),
            BodyWriteErrorAction::RetireNoFurtherFin {
                peer_stop_sending: false
            }
        );
        assert_eq!(
            classify_body_write_error(false, false, false, true, false),
            BodyWriteErrorAction::RetireNoFurtherFin {
                peer_stop_sending: false
            }
        );
        assert_eq!(
            classify_body_write_error(false, false, false, false, true),
            BodyWriteErrorAction::RetireNoFurtherFin {
                peer_stop_sending: false
            }
        );
        assert_eq!(
            classify_body_write_error(false, false, false, false, false),
            BodyWriteErrorAction::Fatal
        );
    }

    #[test]
    fn peer_stop_blocks_body_and_fin() {
        assert_eq!(
            gate_body_write(false, false, true),
            BodyWriteGate::RefuseClosed
        );
        assert_eq!(gate_write_fin(false, true), WriteFinGate::Skip);
    }
}
