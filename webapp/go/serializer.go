package main

import (
	"bytes"

	"github.com/bytedance/sonic/decoder"
	"github.com/bytedance/sonic/encoder"
	"github.com/labstack/echo/v4"
)

type sonicJSONSerializer struct{}

func (j *sonicJSONSerializer) Serialize(c echo.Context, i interface{}, _ string) error {
	buf, err := encoder.Encode(i, 0)
	if err != nil {
		return err
	}
	_, err = c.Response().Write(buf)
	return err
}

func (j *sonicJSONSerializer) Deserialize(c echo.Context, i interface{}) error {
	var buf bytes.Buffer
	buf.ReadFrom(c.Request().Body)
	return decoder.NewDecoder(buf.String()).Decode(i)
}
