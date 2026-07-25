// Differential-testing oracle: an independent OPAQUE implementation
// (github.com/bytemare/opaque) driven with injected randomness, so its output
// is a deterministic function of the case and can be compared byte-for-byte
// against opaque-zig.
//
// Protocol: newline-delimited JSON on stdin, one result object per line on
// stdout, in order. A long-lived process amortises startup across cases and
// holds client state between KE1 and KE3; a malformed or failing case yields
// {"error": "..."} rather than exiting, so a fuzzing run is never interrupted
// by one bad input.
//
// Registration and the client's KE1 are fully deterministic here: the caller
// derives the OPRF blind and the client's ephemeral AKE key from opaque-zig and
// injects them, which sidesteps the fact that the two implementations expand
// seeds into scalars differently. The server's KE2 cannot be pinned that way --
// opaque-zig derives its ephemeral key from a seed internally and never exposes
// the scalar -- so the login path is cross-executed instead: each side consumes
// the other's messages and both must arrive at the same session key.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/bytemare/ecc"
	"github.com/bytemare/ksf"
	"github.com/bytemare/opaque"
)

// ksfParams mirrors opaque-zig's `Ksf.argon2id`: Argon2id with an explicit
// 16-byte all-zero salt and a 64-byte output (opaque.zig `stretch`).
type ksfParams struct {
	Time    uint64 `json:"time"`
	Memory  uint64 `json:"memory"`
	Threads uint64 `json:"threads"`
	Length  int    `json:"length"`
	SaltHex string `json:"salt"`
}

type testCase struct {
	Op        string `json:"op"`
	SessionID string `json:"sessionId"`

	Password string `json:"password"`
	Context  string `json:"context"`

	Blind         string `json:"blind"`
	EnvelopeNonce string `json:"envelopeNonce"`

	OPRFSeed             string `json:"oprfSeed"`
	ServerPrivateKey     string `json:"serverPrivateKey"`
	ServerPublicKey      string `json:"serverPublicKey"`
	CredentialIdentifier string `json:"credentialIdentifier"`

	ClientIdentity string `json:"clientIdentity"`
	ServerIdentity string `json:"serverIdentity"`

	// AKE material.
	ClientEphemeralSecret string `json:"clientEphemeralSecret"`
	ClientNonce           string `json:"clientNonce"`
	MaskingNonce          string `json:"maskingNonce"`
	ServerNonce           string `json:"serverNonce"`

	Record    string `json:"record"`
	KE1       string `json:"ke1"`
	KE2       string `json:"ke2"`
	KE3       string `json:"ke3"`
	ClientMAC string `json:"clientMac"`

	KSF ksfParams `json:"ksf"`
}

type result struct {
	RegistrationRequest  string `json:"registrationRequest,omitempty"`
	RegistrationResponse string `json:"registrationResponse,omitempty"`
	RegistrationRecord   string `json:"registrationRecord,omitempty"`
	ExportKey            string `json:"exportKey,omitempty"`

	KE1        string `json:"ke1,omitempty"`
	KE2        string `json:"ke2,omitempty"`
	KE3        string `json:"ke3,omitempty"`
	ClientMAC  string `json:"clientMac,omitempty"`
	SessionKey string `json:"sessionKey,omitempty"`
	OK         bool   `json:"ok,omitempty"`

	Error string `json:"error,omitempty"`
}

// Live client state between GenerateKE1 and GenerateKE3, which the library
// carries in the Client object.
var sessions = map[string]*opaque.Client{}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1<<20), 1<<24)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	encoder := json.NewEncoder(out)
	for in.Scan() {
		line := in.Bytes()
		if len(line) == 0 {
			continue
		}
		var c testCase
		var r result
		if err := json.Unmarshal(line, &c); err != nil {
			r = result{Error: fmt.Sprintf("bad case: %v", err)}
		} else {
			r = dispatch(&c)
		}
		if err := encoder.Encode(&r); err != nil {
			fmt.Fprintln(os.Stderr, "encode:", err)
			os.Exit(1)
		}
		// Flush per case: the driver reads results synchronously and would
		// otherwise deadlock waiting on a buffered line.
		if err := out.Flush(); err != nil {
			fmt.Fprintln(os.Stderr, "flush:", err)
			os.Exit(1)
		}
	}
}

func dispatch(c *testCase) (r result) {
	// bytemare panics on some malformed group inputs. A panic is a property of
	// the oracle, not a divergence in opaque-zig, so it is reported per case.
	defer func() {
		if p := recover(); p != nil {
			r = result{Error: fmt.Sprintf("panic: %v", p)}
		}
	}()

	switch c.Op {
	case "register":
		return runRegister(c)
	case "loginClientStart":
		return runLoginClientStart(c)
	case "loginClientFinish":
		return runLoginClientFinish(c)
	case "loginServer":
		return runLoginServer(c)
	case "loginServerFinish":
		return runLoginServerFinish(c)
	default:
		return result{Error: "unknown op: " + c.Op}
	}
}

// inputs holds the decoded, validated form of a case.
type inputs struct {
	password             []byte
	context              []byte
	credentialIdentifier []byte
	clientIdentity       []byte
	serverIdentity       []byte
	envelopeNonce        []byte
	oprfSeed             []byte
	serverPublicKey      []byte
	ksfSalt              []byte
	ksfParameters        []uint64
	ksfLength            int
}

func decode(c *testCase) (*inputs, error) {
	var in inputs
	var err error
	for _, field := range []struct {
		dst  *[]byte
		src  string
		name string
	}{
		{&in.password, c.Password, "password"},
		{&in.context, c.Context, "context"},
		{&in.credentialIdentifier, c.CredentialIdentifier, "credentialIdentifier"},
		{&in.envelopeNonce, c.EnvelopeNonce, "envelopeNonce"},
		{&in.oprfSeed, c.OPRFSeed, "oprfSeed"},
		{&in.serverPublicKey, c.ServerPublicKey, "serverPublicKey"},
		{&in.ksfSalt, c.KSF.SaltHex, "ksf.salt"},
	} {
		if *field.dst, err = hex.DecodeString(field.src); err != nil {
			return nil, fmt.Errorf("%s: %w", field.name, err)
		}
	}
	// An absent identity is nil, not an empty non-nil slice: RFC 9807
	// substitutes the corresponding public key when an identity is absent, and
	// a library may reasonably test for nil rather than length. Keeping the
	// distinction means a divergence is attributable to the implementation
	// rather than to this oracle.
	if in.clientIdentity, err = decodeIdentity(c.ClientIdentity); err != nil {
		return nil, fmt.Errorf("clientIdentity: %w", err)
	}
	if in.serverIdentity, err = decodeIdentity(c.ServerIdentity); err != nil {
		return nil, fmt.Errorf("serverIdentity: %w", err)
	}
	in.ksfParameters = []uint64{c.KSF.Time, c.KSF.Memory, c.KSF.Threads}
	in.ksfLength = c.KSF.Length
	return &in, nil
}

func configuration(in *inputs) *opaque.Configuration {
	defaults := opaque.DefaultConfiguration()
	return &opaque.Configuration{
		Context: in.context,
		KDF:     defaults.KDF,
		MAC:     defaults.MAC,
		Hash:    defaults.Hash,
		KSF:     ksf.Argon2id,
		OPRF:    opaque.RistrettoSha512,
		AKE:     opaque.RistrettoSha512,
	}
}

func (in *inputs) clientOptions() *opaque.ClientOptions {
	return &opaque.ClientOptions{
		KSFSalt:       in.ksfSalt,
		KSFLength:     in.ksfLength,
		KSFParameters: in.ksfParameters,
	}
}

func scalar(h string) (*ecc.Scalar, error) {
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	s := opaque.RistrettoSha512.Group().NewScalar()
	if err := s.Decode(raw); err != nil {
		return nil, err
	}
	return s, nil
}

func runRegister(c *testCase) result {
	in, err := decode(c)
	if err != nil {
		return result{Error: err.Error()}
	}

	blind, err := scalar(c.Blind)
	if err != nil {
		return result{Error: "blind: " + err.Error()}
	}

	conf := configuration(in)
	client, err := conf.Client()
	if err != nil {
		return result{Error: "client: " + err.Error()}
	}

	// The blind is injected only at init: the client carries it in state
	// afterwards, and supplying it again at finalize is rejected as a
	// contradictory option.
	initOptions := in.clientOptions()
	initOptions.OPRFBlind = blind

	request, err := client.RegistrationInit(in.password, initOptions)
	if err != nil {
		return result{Error: "RegistrationInit: " + err.Error()}
	}

	server, err := conf.Server()
	if err != nil {
		return result{Error: "server: " + err.Error()}
	}
	if err := setKeyMaterial(server, c, in); err != nil {
		return result{Error: err.Error()}
	}

	response, err := server.RegistrationResponse(request, in.credentialIdentifier, nil)
	if err != nil {
		return result{Error: "RegistrationResponse: " + err.Error()}
	}

	finalizeOptions := in.clientOptions()
	finalizeOptions.RegistrationEnvelopeNonce = in.envelopeNonce

	record, exportKey, err := client.RegistrationFinalize(
		response, in.clientIdentity, in.serverIdentity, finalizeOptions,
	)
	if err != nil {
		return result{Error: "RegistrationFinalize: " + err.Error()}
	}

	return result{
		RegistrationRequest:  hex.EncodeToString(request.Serialize()),
		RegistrationResponse: hex.EncodeToString(response.Serialize()),
		RegistrationRecord:   hex.EncodeToString(record.Serialize()),
		ExportKey:            hex.EncodeToString(exportKey),
	}
}

func setKeyMaterial(server *opaque.Server, c *testCase, in *inputs) error {
	skm := &opaque.ServerKeyMaterial{
		PublicKeyBytes: in.serverPublicKey,
		OPRFGlobalSeed: in.oprfSeed,
		Identity:       in.serverIdentity,
	}
	if c.ServerPrivateKey != "" {
		privateKey, err := scalar(c.ServerPrivateKey)
		if err != nil {
			return fmt.Errorf("serverPrivateKey: %w", err)
		}
		skm.PrivateKey = privateKey
	}
	if err := server.SetKeyMaterial(skm); err != nil {
		return fmt.Errorf("SetKeyMaterial: %w", err)
	}
	return nil
}

// runLoginClientStart produces KE1. With the blind, the ephemeral AKE key and
// the nonce all injected, the message is fully determined and can be compared
// byte-for-byte against opaque-zig's.
func runLoginClientStart(c *testCase) result {
	in, err := decode(c)
	if err != nil {
		return result{Error: err.Error()}
	}

	conf := configuration(in)
	client, err := conf.Client()
	if err != nil {
		return result{Error: "client: " + err.Error()}
	}

	options := in.clientOptions()
	if c.Blind != "" {
		blind, err := scalar(c.Blind)
		if err != nil {
			return result{Error: "blind: " + err.Error()}
		}
		options.OPRFBlind = blind
	}
	ake := &opaque.AKEOptions{}
	if c.ClientEphemeralSecret != "" {
		secret, err := scalar(c.ClientEphemeralSecret)
		if err != nil {
			return result{Error: "clientEphemeralSecret: " + err.Error()}
		}
		ake.SecretKeyShare = secret
	}
	if c.ClientNonce != "" {
		nonce, err := hex.DecodeString(c.ClientNonce)
		if err != nil {
			return result{Error: "clientNonce: " + err.Error()}
		}
		ake.Nonce = nonce
	}
	options.AKE = ake

	ke1, err := client.GenerateKE1(in.password, options)
	if err != nil {
		return result{Error: "GenerateKE1: " + err.Error()}
	}
	sessions[c.SessionID] = client
	return result{KE1: hex.EncodeToString(ke1.Serialize())}
}

func runLoginClientFinish(c *testCase) result {
	in, err := decode(c)
	if err != nil {
		return result{Error: err.Error()}
	}

	client, found := sessions[c.SessionID]
	if !found {
		return result{Error: "no client session " + c.SessionID}
	}
	defer delete(sessions, c.SessionID)

	conf := configuration(in)
	raw, err := hex.DecodeString(c.KE2)
	if err != nil {
		return result{Error: "ke2: " + err.Error()}
	}
	deserializer, err := conf.Deserializer()
	if err != nil {
		return result{Error: "deserializer: " + err.Error()}
	}
	ke2, err := deserializer.KE2(raw)
	if err != nil {
		return result{Error: "KE2 deserialize: " + err.Error()}
	}

	ke3, sessionKey, exportKey, err := client.GenerateKE3(
		ke2, in.clientIdentity, in.serverIdentity, in.clientOptions(),
	)
	if err != nil {
		return result{Error: "GenerateKE3: " + err.Error()}
	}
	return result{
		KE3:        hex.EncodeToString(ke3.Serialize()),
		SessionKey: hex.EncodeToString(sessionKey),
		ExportKey:  hex.EncodeToString(exportKey),
		OK:         true,
	}
}

func runLoginServer(c *testCase) result {
	in, err := decode(c)
	if err != nil {
		return result{Error: err.Error()}
	}

	conf := configuration(in)
	server, err := conf.Server()
	if err != nil {
		return result{Error: "server: " + err.Error()}
	}
	if err := setKeyMaterial(server, c, in); err != nil {
		return result{Error: err.Error()}
	}

	deserializer, err := conf.Deserializer()
	if err != nil {
		return result{Error: "deserializer: " + err.Error()}
	}
	recordBytes, err := hex.DecodeString(c.Record)
	if err != nil {
		return result{Error: "record: " + err.Error()}
	}
	registrationRecord, err := deserializer.RegistrationRecord(recordBytes)
	if err != nil {
		return result{Error: "record deserialize: " + err.Error()}
	}
	ke1Bytes, err := hex.DecodeString(c.KE1)
	if err != nil {
		return result{Error: "ke1: " + err.Error()}
	}
	ke1, err := deserializer.KE1(ke1Bytes)
	if err != nil {
		return result{Error: "KE1 deserialize: " + err.Error()}
	}

	options := &opaque.ServerOptions{}
	if c.MaskingNonce != "" {
		maskingNonce, err := hex.DecodeString(c.MaskingNonce)
		if err != nil {
			return result{Error: "maskingNonce: " + err.Error()}
		}
		options.MaskingNonce = maskingNonce
	}
	if c.ServerNonce != "" {
		serverNonce, err := hex.DecodeString(c.ServerNonce)
		if err != nil {
			return result{Error: "serverNonce: " + err.Error()}
		}
		options.AKE = &opaque.AKEOptions{Nonce: serverNonce}
	}

	ke2, output, err := server.GenerateKE2(ke1, &opaque.ClientRecord{
		RegistrationRecord:   registrationRecord,
		CredentialIdentifier: in.credentialIdentifier,
		ClientIdentity:       in.clientIdentity,
	}, options)
	if err != nil {
		return result{Error: "GenerateKE2: " + err.Error()}
	}

	return result{
		KE2:        hex.EncodeToString(ke2.Serialize()),
		ClientMAC:  hex.EncodeToString(output.ClientMAC),
		SessionKey: hex.EncodeToString(output.SessionSecret),
	}
}

func runLoginServerFinish(c *testCase) result {
	in, err := decode(c)
	if err != nil {
		return result{Error: err.Error()}
	}
	conf := configuration(in)
	server, err := conf.Server()
	if err != nil {
		return result{Error: "server: " + err.Error()}
	}
	deserializer, err := conf.Deserializer()
	if err != nil {
		return result{Error: "deserializer: " + err.Error()}
	}
	ke3Bytes, err := hex.DecodeString(c.KE3)
	if err != nil {
		return result{Error: "ke3: " + err.Error()}
	}
	ke3, err := deserializer.KE3(ke3Bytes)
	if err != nil {
		return result{Error: "KE3 deserialize: " + err.Error()}
	}
	expected, err := hex.DecodeString(c.ClientMAC)
	if err != nil {
		return result{Error: "clientMac: " + err.Error()}
	}
	if err := server.LoginFinish(ke3, expected); err != nil {
		return result{Error: "LoginFinish: " + err.Error()}
	}
	return result{OK: true}
}

// decodeIdentity returns nil for an absent identity, so callers can tell
// "no identity" from "zero-length identity".
func decodeIdentity(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}
