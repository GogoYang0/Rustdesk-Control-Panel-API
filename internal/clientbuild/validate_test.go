package clientbuild

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateProfileName(t *testing.T) {
	name, key, err := ValidateProfileName(" Ops ")
	require.NoError(t, err)
	require.Equal(t, "Ops", name)
	require.Equal(t, "ops", key)
	_, _, err = ValidateProfileName(strings.Repeat("a", 65))
	require.Error(t, err)
	_, _, err = ValidateProfileName("bad\nname")
	require.Error(t, err)
}

func TestValidateAppName(t *testing.T) {
	name, err := ValidateAppName(" Acme Ops ")
	require.NoError(t, err)
	require.Equal(t, "Acme Ops", name)
	for _, bad := range []string{"RustDesk", ".", "..", "a/b", `a\b`, strings.Repeat("a", 33)} {
		_, err := ValidateAppName(bad)
		require.Errorf(t, err, "app name %q must be rejected", bad)
	}
	_, err = ValidateAppName(strings.Repeat("界", 32))
	require.NoError(t, err)
}

func TestValidatePlatforms(t *testing.T) {
	got, err := ValidatePlatforms(
		[]string{"android-arm64", "windows-x64", "android-arm64"},
		SupportedPlatforms,
	)
	require.NoError(t, err)
	require.Equal(t, []string{"windows-x64", "android-arm64"}, got)
	_, err = ValidatePlatforms([]string{"ios"}, SupportedPlatforms)
	require.Error(t, err)
	_, err = ValidatePlatforms(nil, SupportedPlatforms)
	require.Error(t, err)
}

func TestValidateServerKey(t *testing.T) {
	require.NoError(t, ValidateServerKey("dGVzdC1rZXktMDEyMzQ1Njc4OWFiY2RlZmdoaWo="))
	require.Error(t, ValidateServerKey(strings.Repeat("a", 15)))
	require.Error(t, ValidateServerKey(`bad"key`))
}

func TestDeriveServer(t *testing.T) {
	got, err := DeriveServer("relay.example.com", 21116)
	require.NoError(t, err)
	require.Equal(t, "relay.example.com:21117", got)
	_, err = DeriveServer("", 21116)
	require.Error(t, err)
	got, err = DeriveServer("2001:db8::1", 21116)
	require.NoError(t, err)
	require.Equal(t, "[2001:db8::1]:21117", got)
}

func TestValidateLogoPNG(t *testing.T) {
	logo, err := ValidateLogoPNG(makePNG(t, 256, 256))
	require.NoError(t, err)
	require.Equal(t, 256, logo.Width)
	require.Equal(t, 256, logo.Height)
	require.Len(t, logo.SHA256, 64)
	require.NotEmpty(t, logo.PNG)

	_, err = ValidateLogoPNG(makePNG(t, 128, 128))
	require.Error(t, err)
	_, err = ValidateLogoPNG(craftPNGHeader(100000, 100000))
	require.Error(t, err)
	require.Contains(t, err.Error(), "dimensions")
	_, err = ValidateLogoPNG(make([]byte, 1<<20+1))
	require.Error(t, err)
}

func makePNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for x := 0; x < w; x++ {
		for y := 0; y < h; y++ {
			img.Set(x, y, color.RGBA{R: uint8(x), G: uint8(y), B: 128, A: 255})
		}
	}
	var buf bytes.Buffer
	require.NoError(t, png.Encode(&buf, img))
	return buf.Bytes()
}

func craftPNGHeader(width, height uint32) []byte {
	sig := []byte{137, 80, 78, 71, 13, 10, 26, 10}
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], width)
	binary.BigEndian.PutUint32(ihdr[4:8], height)
	ihdr[8] = 8 // bit depth
	ihdr[9] = 6 // truecolour with alpha
	out := append([]byte{}, sig...)
	out = append(out, pngChunk("IHDR", ihdr)...)
	out = append(out, pngChunk("IEND", nil)...)
	return out
}

func pngChunk(typ string, data []byte) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(data)))
	out = append(out, typ...)
	out = append(out, data...)
	crc := crc32.ChecksumIEEE(append([]byte(typ), data...))
	c := make([]byte, 4)
	binary.BigEndian.PutUint32(c, crc)
	return append(out, c...)
}
