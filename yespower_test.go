package yespower

import (
	"fmt"
	"testing"
)

func TestYespower(t *testing.T) {
	// NOTE: 'in' values copied directly from C implementation tests
	in := []byte{0x00, 0x03, 0x06, 0x09, 0x0c, 0x0f, 0x12, 0x15,
		0x18, 0x1b, 0x1e, 0x21, 0x24, 0x27, 0x2a, 0x2d,
		0x30, 0x33, 0x36, 0x39, 0x3c, 0x3f, 0x42, 0x45,
		0x48, 0x4b, 0x4e, 0x51, 0x54, 0x57, 0x5a, 0x5d,
		0x60, 0x63, 0x66, 0x69, 0x6c, 0x6f, 0x72, 0x75,
		0x78, 0x7b, 0x7e, 0x81, 0x84, 0x87, 0x8a, 0x8d,
		0x90, 0x93, 0x96, 0x99, 0x9c, 0x9f, 0xa2, 0xa5,
		0xa8, 0xab, 0xae, 0xb1, 0xb4, 0xb7, 0xba, 0xbd,
		0xc0, 0xc3, 0xc6, 0xc9, 0xcc, 0xcf, 0xd2, 0xd5,
		0xd8, 0xdb, 0xde, 0xe1, 0xe4, 0xe7, 0xea, 0xed}

	examples := []struct {
		N, r            int
		persToken, want string
	}{
		// NOTE: 'want' values copied directly from C implementation tests
		{N: 2048, r: 8, persToken: "", want: "69e0e895b3df7aeeb837d71fe199e9d34f7ec46ecbca7a2c4308e51857ae9b46"},
		{N: 4096, r: 16, persToken: "", want: "33fb8f063824a4a020f63dca535f5ca66ab5576468c75d1ccaac7542f76495ac"},
		{N: 4096, r: 32, persToken: "", want: "771aeefda8fe79a0825bc7f2aee162ab5578574639ffc6ca3723cc18e5e3e285"},
		{N: 2048, r: 32, persToken: "", want: "d5efb813cd263e9b34540130233cbbc6a921fbff3431e5ec1a1abde2aea6ff4d"},
		{N: 1024, r: 32, persToken: "", want: "501b792db42e388f6e7d453c95d03a12a36016a5154a688390ddc609a40c6799"},
		{N: 1024, r: 32, persToken: "personality test", want: "1f0269acf565c49adc0ef9b8f26ab3808cdc38394a254fddeedcc3aacff6ad9d"},
	}

	for _, tt := range examples {
		got := Yespower(in, tt.N, tt.r, tt.persToken)
		if got != tt.want {
			t.Errorf("got %s want %s", got, tt.want)
		}
	}
}

func TestYescrypt(t *testing.T) {
	// NOTE: 'in' values copied directly from C implementation tests
	in := []byte{0x00, 0x03, 0x06, 0x09, 0x0c, 0x0f, 0x12, 0x15,
		0x18, 0x1b, 0x1e, 0x21, 0x24, 0x27, 0x2a, 0x2d,
		0x30, 0x33, 0x36, 0x39, 0x3c, 0x3f, 0x42, 0x45,
		0x48, 0x4b, 0x4e, 0x51, 0x54, 0x57, 0x5a, 0x5d,
		0x60, 0x63, 0x66, 0x69, 0x6c, 0x6f, 0x72, 0x75,
		0x78, 0x7b, 0x7e, 0x81, 0x84, 0x87, 0x8a, 0x8d,
		0x90, 0x93, 0x96, 0x99, 0x9c, 0x9f, 0xa2, 0xa5,
		0xa8, 0xab, 0xae, 0xb1, 0xb4, 0xb7, 0xba, 0xbd,
		0xc0, 0xc3, 0xc6, 0xc9, 0xcc, 0xcf, 0xd2, 0xd5,
		0xd8, 0xdb, 0xde, 0xe1, 0xe4, 0xe7, 0xea, 0xed}

	examples := []struct {
		N, r            int
		persToken, want string
	}{
		// NOTE: 'want' values copied directly from C implementation tests
		{N: 2048, r: 8, persToken: "Client Key", want: "a59fec4c4fdda16e3b1405adda66d525b68e7cadfcfe6ac066c7ad118cd80590"},
		{N: 2048, r: 8, persToken: pers_bsty_magic, want: "5ea2b2956a9eace30a3237ff1d441edee1dc25aab8f0ea15c12165f83a7bc265"},
		{N: 4096, r: 16, persToken: "Client Key", want: "927e72d0ded3d80475473f40f1743c67289d453d5242d4f55af4e325e06699c5"},
		{N: 4096, r: 24, persToken: "Jagaricoin", want: "0e1366973211e7fea8ad9d81989c84a254d968c9d333dd8ff099324f38611e04"},
		{N: 4096, r: 32, persToken: "WaviBanana", want: "3ae05abb3c5cf6f75415a92554c98d50e38ec9552cfa78373616f480b24e559f"},
		{N: 2048, r: 32, persToken: "Client Key", want: "560a891b5ca2e1c636111a9ff7c894a5d0a2602f43fdcfa5949b95e22fe4461e"},
		{N: 1024, r: 32, persToken: "Client Key", want: "2a79e53d1be6669bc556ccc417bce3d22a74a232f56b8e1d39b45792675de108"},
		{N: 2048, r: 8, persToken: "", want: "5ecbd8e8d7c90baed4bbf8916a1225dcc3c65f5c9165bae81cdde3cffad128e8"},
	}

	for _, tt := range examples {
		if tt.persToken == pers_bsty_magic {
			tt.persToken = fmt.Sprintf("%s", in)
		}
		got := Yescrypt(in, tt.N, tt.r, tt.persToken)
		if got != tt.want {
			t.Errorf("got %s want %s", got, tt.want)
		}
	}
}

var result string

func bench(b *testing.B, version string, r, N int, pers string) {
	in := []byte{0x00, 0x03, 0x06, 0x09, 0x0c, 0x0f, 0x12, 0x15,
		0x18, 0x1b, 0x1e, 0x21, 0x24, 0x27, 0x2a, 0x2d,
		0x30, 0x33, 0x36, 0x39, 0x3c, 0x3f, 0x42, 0x45,
		0x48, 0x4b, 0x4e, 0x51, 0x54, 0x57, 0x5a, 0x5d,
		0x60, 0x63, 0x66, 0x69, 0x6c, 0x6f, 0x72, 0x75,
		0x78, 0x7b, 0x7e, 0x81, 0x84, 0x87, 0x8a, 0x8d,
		0x90, 0x93, 0x96, 0x99, 0x9c, 0x9f, 0xa2, 0xa5,
		0xa8, 0xab, 0xae, 0xb1, 0xb4, 0xb7, 0xba, 0xbd,
		0xc0, 0xc3, 0xc6, 0xc9, 0xcc, 0xcf, 0xd2, 0xd5,
		0xd8, 0xdb, 0xde, 0xe1, 0xe4, 0xe7, 0xea, 0xed}

	var ignore string
	for i := 0; i < b.N; i++ {
		ignore = yespower(version, in, N, r, pers)
		result = ignore
	}
}

// Benchmark the Yespower algo
func BenchmarkYespower_1024_32_wo_pers(b *testing.B) { bench(b, YESPOWER_1_0, 1024, 32, "") }
func BenchmarkYespower_1024_32_w__pers(b *testing.B) {
	bench(b, YESPOWER_1_0, 1024, 32, "personality test")
}
func BenchmarkYespower_2048_08_wo_pers(b *testing.B) { bench(b, YESPOWER_1_0, 2048, 8, "") }
func BenchmarkYespower_2048_32_wo_pers(b *testing.B) { bench(b, YESPOWER_1_0, 2038, 32, "") }
func BenchmarkYespower_4096_16_wo_pers(b *testing.B) { bench(b, YESPOWER_1_0, 4096, 16, "") }
func BenchmarkYespower_4096_32_wo_pers(b *testing.B) { bench(b, YESPOWER_1_0, 4096, 32, "") }

// Benchmark the Yescrypt algo
func BenchmarkYescrypt_1024_32_w__pers(b *testing.B) { bench(b, YESPOWER_0_5, 2048, 8, "Client Key") }
func BenchmarkYescrypt_2048_08_w__pers(b *testing.B) {
	bench(b, YESPOWER_0_5, 2048, 8, pers_bsty_magic)
}
func BenchmarkYescrypt_2048_32_w__pers(b *testing.B) { bench(b, YESPOWER_0_5, 2048, 8, "Client Key") }
func BenchmarkYescrypt_4096_16_w__pers(b *testing.B) { bench(b, YESPOWER_0_5, 4096, 16, "Client Key") }
func BenchmarkYescrypt_4096_24_w__pers(b *testing.B) { bench(b, YESPOWER_0_5, 4096, 24, "Jagaricoin") }
func BenchmarkYescrypt_4096_32_w__pers(b *testing.B) { bench(b, YESPOWER_0_5, 4096, 32, "WaviBanana") }
func BenchmarkYescrypt_4096_32_wo_pers(b *testing.B) { bench(b, YESPOWER_0_5, 4096, 32, "") }
