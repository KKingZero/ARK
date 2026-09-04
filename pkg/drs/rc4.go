package drs

// rc4Cipher is a tiny RC4 (MS-DRSR attribute encryption).
type rc4Cipher struct {
	s    [256]byte
	i, j byte
}

func newRC4(key []byte) *rc4Cipher {
	var c rc4Cipher
	for i := 0; i < 256; i++ {
		c.s[i] = byte(i)
	}
	var j byte
	for i := 0; i < 256; i++ {
		j += c.s[i] + key[i%len(key)]
		c.s[i], c.s[j] = c.s[j], c.s[i]
	}
	return &c
}

func (c *rc4Cipher) XORKeyStream(dst, src []byte) {
	for k, v := range src {
		c.i++
		c.j += c.s[c.i]
		c.s[c.i], c.s[c.j] = c.s[c.j], c.s[c.i]
		dst[k] = v ^ c.s[c.s[c.i]+c.s[c.j]]
	}
}
