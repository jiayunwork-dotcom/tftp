package tftp

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// parseWindowsize parses and validates an RFC 7440 windowsize option
// value. Only decimal integers in the 1..65535 range are accepted.
func parseWindowsize(v string) (int, bool) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}

// negotiateWindowsize validates the windowsize requested by the peer
// against the local maximum window. The option is accepted only when
// the local side is enabled (maxWindow in 1..65535) and the requested
// value is a decimal integer in 1..65535; the negotiated value is the
// smaller of the two. ok is false when the option must be ignored.
func negotiateWindowsize(requested string, maxWindow int) (int, bool) {
	if maxWindow < 1 {
		return 0, false
	}
	n, ok := parseWindowsize(requested)
	if !ok {
		return 0, false
	}
	if n > maxWindow {
		n = maxWindow
	}
	return n, true
}

// readFromWindow implements the sending side of RFC 7440: after the
// OACK has been acknowledged the sender bursts a full window of DATA
// blocks and then waits for the ACK of the last block in the window.
func (s *sender) readFromWindow(r io.Reader) (n int64, err error) {
	s.block = 1 // data blocks start with block 1
	win := s.winSize
	blockCap := len(s.send) - 4
	// One reusable slot per block in the window; slots are allocated
	// lazily as blocks are read and reused across windows.
	slots := make([][]byte, win)
	lens := make([]int, win)
	for {
		// Fill the window with blocks coming from the reader.
		num := 0
		terminal := false
		for k := 0; k < win; k++ {
			if slots[k] == nil {
				slots[k] = make([]byte, blockCap+4)
				binary.BigEndian.PutUint16(slots[k][0:2], opDATA)
			}
			lx, rerr := io.ReadFull(r, slots[k][4:])
			n += int64(lx)
			if rerr != nil && rerr != io.ErrUnexpectedEOF {
				if rerr == io.EOF {
					// The reader is exhausted. When the last block
					// was a full block, send an empty block that
					// marks the end of the transfer.
					binary.BigEndian.PutUint16(slots[k][2:4], s.block+uint16(k))
					lens[k] = 4
					num = k + 1
					terminal = true
					break
				}
				s.abort(rerr)
				return n, rerr
			}
			binary.BigEndian.PutUint16(slots[k][2:4], s.block+uint16(k))
			lens[k] = 4 + lx
			num = k + 1
			if lx < blockCap {
				// A short block terminates the transfer and the
				// current window.
				terminal = true
				break
			}
		}
		acked, err := s.sendWindowWithRetry(s.block, slots[:num], lens[:num])
		if err != nil {
			s.abort(err)
			return n, err
		}
		s.block = acked + 1
		if terminal {
			if s.hook != nil {
				s.hook.OnSuccess(s.buildTransferStats())
			}
			return n, nil
		}
	}
}

// sendWindowWithRetry sends all blocks covering
// base..base+len(bufs)-1 in a single burst and waits for the ACK of the
// last block. An ACK that only reaches a block in the middle of the
// window is treated as a cumulative acknowledgement: acknowledged
// blocks are not retransmitted and the remaining tail is sent right
// away. On timeout every still unacknowledged block is retransmitted,
// using the configured timeout, retries and backoff.
func (s *sender) sendWindowWithRetry(base uint16, bufs [][]byte, lens []int) (uint16, error) {
	num := len(bufs)
	last := base + uint16(num) - 1
	first := 0 // index of the first unacknowledged block
	s.retry.reset()
	for {
		if err := s.conn.setDeadline(s.timeout); err != nil {
			return 0, err
		}
		for k := first; k < num; k++ {
			if err := s.conn.sendTo(bufs[k][:lens[k]], s.addr); err != nil {
				return 0, err
			}
			s.datagramsSent++
		}
		partial := false
		for !partial {
			n, addr, err := s.conn.readFrom(s.receive)
			if err != nil {
				if _, ok := err.(net.Error); !ok || s.retry.count() >= s.retries {
					return 0, err
				}
				// Retransmit the whole unacknowledged part of the
				// window after backing off.
				s.retry.backoff()
				break
			}
			if !addr.IP.Equal(s.addr.IP) || (s.tid != 0 && addr.Port != s.tid) {
				continue
			}
			p, err := parsePacket(s.receive[:n])
			if err != nil {
				continue
			}
			s.tid = addr.Port
			switch p := p.(type) {
			case pACK:
				bn := p.block()
				if bn == last {
					s.datagramsAcked++
					return bn, nil
				}
				if bn >= base+uint16(first) && bn < last {
					// Partial acknowledgement: blocks up to bn are
					// in, send the tail without touching the blocks
					// already acknowledged.
					first = int(bn-base) + 1
					s.retry.reset()
					partial = true
				}
				// A stale/duplicate ACK: keep waiting.
			case pERROR:
				return 0, fmt.Errorf("sending block %d: code=%d, error: %s",
					last, p.code(), p.message())
			}
		}
	}
}

// writeToWindow implements the receiving side of RFC 7440: DATA blocks
// are acknowledged once per full window (or when the terminating short
// block arrives) with a single cumulative ACK.
func (r *receiver) writeToWindow(w io.Writer) (n int64, err error) {
	binary.BigEndian.PutUint16(r.send[0:2], opACK)
	// After option negotiation block 1 may already be buffered
	// (server side: DATA(1) was read right after the OACK). On the
	// client side nothing is buffered and the OACK needs ACK(0).
	r.block = 1
	buffered := r.l > 0
	if !buffered {
		if err := r.sendAckBlock(0); err != nil {
			r.abort(err)
			return 0, err
		}
	}
	for {
		count := 0
		terminal := false
		if buffered {
			buffered = false
			l := r.l
			r.l = 0
			nn, werr := w.Write(r.receive[4:l])
			n += int64(nn)
			if werr != nil {
				r.abort(werr)
				return n, werr
			}
			count = 1
			if l < len(r.receive) {
				terminal = true
			} else {
				r.block++
			}
		}
		for !terminal && count < r.winSize {
			c, _, rerr := r.receiveWindowData()
			if rerr != nil {
				r.abort(rerr)
				return n, rerr
			}
			nn, werr := w.Write(r.receive[4:c])
			n += int64(nn)
			if werr != nil {
				r.abort(werr)
				return n, werr
			}
			count++
			if c < len(r.receive) {
				terminal = true
			} else {
				r.block++
			}
		}
		if terminal {
			// The final ACK is sent by terminate(), as in the
			// regular code path.
			if r.autoTerm {
				r.terminate()
			}
			return n, nil
		}
		// Acknowledge the last block of the full window.
		if err := r.sendAckBlock(r.block - 1); err != nil {
			r.abort(err)
			return n, err
		}
	}
}

// receiveWindowData waits for the next expected DATA block (numbered
// r.block). On a block number mismatch it immediately re-sends the
// cumulative ACK covering the last block received continuously
// (r.block-1). While waiting for the next block the same ACK is
// retransmitted on timeout, honoring retries and backoff.
func (r *receiver) receiveWindowData() (int, *net.UDPAddr, error) {
	r.retry.reset()
	for {
		if err := r.conn.setDeadline(r.timeout); err != nil {
			return 0, nil, err
		}
		c, addr, err := r.conn.readFrom(r.receive)
		if err != nil {
			if _, ok := err.(net.Error); ok && r.retry.count() < r.retries {
				if aerr := r.sendAckBlock(r.block - 1); aerr != nil {
					return 0, nil, aerr
				}
				r.retry.backoff()
				continue
			}
			return 0, nil, err
		}
		if !addr.IP.Equal(r.addr.IP) || (r.tid != 0 && addr.Port != r.tid) {
			continue
		}
		p, err := parsePacket(r.receive[:c])
		if err != nil {
			return 0, addr, err
		}
		r.tid = addr.Port
		switch p := p.(type) {
		case pDATA:
			if p.block() == r.block {
				r.datagramsAcked++
				return c, addr, nil
			}
			// Out of sequence block: acknowledge the last block
			// received continuously again, right away.
			if err := r.sendAckBlock(r.block - 1); err != nil {
				return 0, addr, err
			}
		case pOACK:
			// Duplicate OACK (the preceding ACK(0) was lost):
			// answer with ACK(0) again.
			if err := r.sendAckBlock(0); err != nil {
				return 0, addr, err
			}
		case pERROR:
			return 0, addr, fmt.Errorf("code: %d, message: %s",
				p.code(), p.message())
		}
	}
}

// sendAckBlock sends an ACK packet for the given block number.
func (r *receiver) sendAckBlock(block uint16) error {
	binary.BigEndian.PutUint16(r.send[0:2], opACK)
	binary.BigEndian.PutUint16(r.send[2:4], block)
	if err := r.conn.sendTo(r.send[:4], r.addr); err != nil {
		return err
	}
	r.datagramsSent++
	return nil
}
