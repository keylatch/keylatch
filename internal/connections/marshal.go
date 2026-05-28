package connections

import "encoding/json"

// marshalConnection serialises a Connection to JSON bytes.
func marshalConnection(c *Connection) ([]byte, error) {
	return json.Marshal(c)
}

// unmarshalConnection deserialises JSON bytes into a Connection.
func unmarshalConnection(data []byte) (*Connection, error) {
	var c Connection
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
