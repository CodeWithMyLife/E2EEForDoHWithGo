package fastime

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

// 流式加密帧格式（服务端与本程序必须一致）：
//
//	[u32be 明文长度][12B 随机 nonce][密文 + 16B GCM tag]
//
// 每帧独立随机 nonce，天然避免 nonce 复用；逐帧解密即可流式输出，
// 内存占用恒定，与数据总大小无关。
//
// GET 场景下帧整体再做 base64url（无填充）编码，即可安全放进 URL 的 time= 参数。
type streamCipher struct {
	aead cipher.AEAD
	pool sync.Pool // 帧缓冲区池：高并发下复用内存，减少 GC 压力与 CPU 能耗
}

func newStreamCipher(key []byte) (*streamCipher, error) {
	block, err := aes.NewCipher(key) // 16 字节 = AES-128，自动使用 AES-NI / ARM CE 硬件加速
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &streamCipher{
		aead: aead,
		pool: sync.Pool{New: func() any { return make([]byte, 0, 1024) }},
	}, nil
}

// Encrypt 把一段明文加密为单个帧。
func (s *streamCipher) Encrypt(plain []byte) ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := s.aead.Seal(nil, nonce, plain, nil)

	buf := s.pool.Get().([]byte)[:0]
	defer s.pool.Put(buf[:0])
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(plain)))
	buf = append(buf, lb[:]...)
	buf = append(buf, nonce...)
	buf = append(buf, ct...)
	// 拷贝出独立副本后归还池
	out := make([]byte, len(buf))
	copy(out, buf)
	return out, nil
}

// EncryptForQuery 加密并做 base64url(无填充) 编码，专供 GET 的 time= 参数。
// 使用紧凑帧：[12B nonce][密文+tag]，省略 4B 长度头——URL 参数本身定长，
// 上游解码后总长 - 28 即明文长度，长度头是纯冗余。
func (s *streamCipher) EncryptForQuery(plain []byte) (string, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := s.aead.Seal(nil, nonce, plain, nil)
	raw := make([]byte, 0, 12+len(ct))
	raw = append(raw, nonce...)
	raw = append(raw, ct...)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

const maxFrame = 4 << 20 // 单帧明文上限 4MB，防恶意长度头

// DecryptStream 逐帧解密 r，解密出一帧就立刻写入 w 并调用 flush（可为 nil），
// 实现真正的流式响应：客户端不用等整个 body 传完。
func (s *streamCipher) DecryptStream(r io.Reader, w io.Writer, flush func()) error {
	var hdr [16]byte // 4B 长度 + 12B nonce
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil // 干净的流结束
			}
			return err
		}
		n := binary.BigEndian.Uint32(hdr[:4])
		if n > maxFrame {
			return errors.New("帧长度超过上限")
		}
		ct := make([]byte, int(n)+16)
		if _, err := io.ReadFull(r, ct); err != nil {
			return err
		}
		pt, err := s.aead.Open(nil, hdr[4:], ct, nil)
		if err != nil {
			return err // tag 校验失败 = 数据被篡改，立即终止
		}
		if _, err := w.Write(pt); err != nil {
			return err
		}
		if flush != nil {
			flush()
		}
	}
}
