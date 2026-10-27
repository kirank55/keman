package cryptoenc

import "encoding/base64"

func decodeStd(s string) ([]byte, error)    { return base64.StdEncoding.DecodeString(s) }
func decodeRawStd(s string) ([]byte, error) { return base64.RawStdEncoding.DecodeString(s) }
func decodeURL(s string) ([]byte, error)    { return base64.URLEncoding.DecodeString(s) }
func decodeRawURL(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
