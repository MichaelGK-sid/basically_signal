// Implementation of a forward-secure, end-to-end encrypted messaging client
// supporting key compromise recovery and out-of-order message delivery.
// Directly inspired by Signal/Double-ratchet protocol but missing a few
// features. No asynchronous handshake support (pre-keys) for example.
//
// SECURITY WARNING: This code is meant for educational purposes and may
// contain vulnerabilities or other bugs. Please do not use it for
// security-critical applications.
//
// GRADING NOTES: This is the only file you need to modify for this assignment.
// You may add additional support files if desired. You should modify this file
// to implement the intended protocol, but preserve the function signatures
// for the following methods to ensure your implementation will work with
// standard test code:
//
// *NewChatter
// *EndSession
// *InitiateHandshake
// *ReturnHandshake
// *FinalizeHandshake
// *SendMessage
// *ReceiveMessage
//
// In addition, you'll need to keep all of the following structs' fields:
//
// *Chatter
// *Session
// *Message
//
// You may add fields if needed (not necessary) but don't rename or delete
// any existing fields.
//
// Original version
// Joseph Bonneau February 2019

package chatterbox

import (
	//	"bytes" //un-comment for helpers like bytes.equal

	"encoding/binary"
	"errors"
	//	"fmt" //un-comment if you want to do any debug printing.
)

// Labels for key derivation

// Label for generating a check key from the initial root.
// Used for verifying the results of a handshake out-of-band.
const HANDSHAKE_CHECK_LABEL byte = 0x11

// Label for ratcheting the root key after deriving a key chain from it
const ROOT_LABEL = 0x22

// Label for ratcheting the main chain of keys
const CHAIN_LABEL = 0x33

// Label for deriving message keys from chain keys
const KEY_LABEL = 0x44

// Chatter represents a chat participant. Each Chatter has a single long-term
// key Identity, and a map of open sessions with other users (indexed by their
// identity keys). You should not need to modify this.
type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
}

// Session represents an open session between one chatter and another.
// You should not need to modify this, though you can add additional fields
// if you want to.
type Session struct {
	MyDHRatchet       *KeyPair
	PartnerDHRatchet  *PublicKey
	RootChain         *SymmetricKey
	SendChain         *SymmetricKey
	ReceiveChain      *SymmetricKey
	CachedReceiveKeys map[int]*SymmetricKey
	SendCounter       int
	LastUpdate        int
	ReceiveCounter    int
	IsSender          bool
	LR                int
	LS                int
}

// Message represents a message as sent over an untrusted network.
// The first 5 fields are send unencrypted (but should be authenticated).
// The ciphertext contains the (encrypted) communication payload.
// You should not need to modify this.
type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	Counter       int
	LastUpdate    int
	Ciphertext    []byte
	IV            []byte
}

// EncodeAdditionalData encodes all of the non-ciphertext fields of a message
// into a single byte array, suitable for use as additional authenticated data
// in an AEAD scheme. You should not need to modify this code.
func (m *Message) EncodeAdditionalData() []byte {
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)

	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))

	if m.Sender != nil {
		copy(buf[8:], m.Sender.Fingerprint())
	}
	if m.Receiver != nil {
		copy(buf[8+FINGERPRINT_LENGTH:], m.Receiver.Fingerprint())
	}
	if m.NextDHRatchet != nil {
		copy(buf[8+2*FINGERPRINT_LENGTH:], m.NextDHRatchet.Fingerprint())
	}

	return buf
}

// NewChatter creates and initializes a new Chatter object. A long-term
// identity key is created and the map of sessions is initialized.
// You should not need to modify this code.
func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = GenerateKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

// EndSession erases all data for a session with the designated partner.
// All outstanding key material should be zeroized and the session erased.
func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return errors.New("Don't have that session open to tear down")
	}

	session := c.Sessions[*partnerIdentity]
	if session.RootChain != nil {
		session.RootChain.Zeroize()
	}
	if session.SendChain != nil {
		session.SendChain.Zeroize()
	}
	if session.ReceiveChain != nil {
		session.ReceiveChain.Zeroize()
	}

	for _, key := range session.CachedReceiveKeys {
		if key != nil {
			key.Zeroize()
		}
	}

	session.MyDHRatchet.PrivateKey.Zeroize()

	delete(c.Sessions, *partnerIdentity)

	// TODO: your code here to zeroize remaining state

	return nil
}

// InitiateHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the initiator.
func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("Already have session open")
	}
	var ephemeralKey = GenerateKeyPair()
	c.Sessions[*partnerIdentity] = &Session{
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		MyDHRatchet:       ephemeralKey}

	return &ephemeralKey.PublicKey, nil
}

// ReturnHandshake prepares the second message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the responder.
func (c *Chatter) ReturnHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, nil, errors.New("Already have session open")
	}
	var ephemeralKey = GenerateKeyPair()
	hgAb := DHCombine(partnerIdentity, &ephemeralKey.PrivateKey)
	hgaB := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	hgab := DHCombine(partnerEphemeral, &ephemeralKey.PrivateKey)
	var symmetricKey *SymmetricKey = CombineKeys(hgAb, hgaB, hgab)

	c.Sessions[*partnerIdentity] = &Session{
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		// TODO: your code here
		MyDHRatchet:      ephemeralKey,
		PartnerDHRatchet: partnerEphemeral,
		RootChain:        symmetricKey}

	checkKey := symmetricKey.DeriveKey(HANDSHAKE_CHECK_LABEL)

	session := c.Sessions[*partnerIdentity]
	session.SendChain = symmetricKey.DeriveKey(CHAIN_LABEL)
	session.ReceiveChain = symmetricKey.DeriveKey(CHAIN_LABEL)
	session.LS = 0
	session.LR = 0
	session.SendCounter = 1
	session.MyDHRatchet = ephemeralKey
	session.IsSender = false
	session.ReceiveCounter = 1

	hgAb.Zeroize()
	hgaB.Zeroize()
	hgab.Zeroize()

	return &ephemeralKey.PublicKey, checkKey, nil

}

// FinalizeHandshake lets the initiator receive the responder's ephemeral key
// and finalize the handshake.The partner which calls this method is the initiator.
func (c *Chatter) FinalizeHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't finalize session, not yet open")
	}

	session := c.Sessions[*partnerIdentity]
	hgAb := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	hgaB := DHCombine(partnerIdentity, &session.MyDHRatchet.PrivateKey)
	hgab := DHCombine(partnerEphemeral, &session.MyDHRatchet.PrivateKey)
	var symmetricKey *SymmetricKey = CombineKeys(hgAb, hgaB, hgab)
	session.RootChain = symmetricKey
	session.SendChain = symmetricKey.DeriveKey(CHAIN_LABEL)
	session.PartnerDHRatchet = partnerEphemeral
	session.ReceiveChain = symmetricKey.DeriveKey(CHAIN_LABEL)
	session.IsSender = true
	checkKey := symmetricKey.DeriveKey(HANDSHAKE_CHECK_LABEL)
	session.LS = 0
	session.LR = 0
	session.SendCounter = 1
	session.ReceiveCounter = 1

	hgAb.Zeroize()
	hgaB.Zeroize()
	hgab.Zeroize()

	return checkKey, nil
}

// SendMessage is used to send the given plaintext string as a message.
// You'll need to implement the code to ratchet, derive keys and encrypt this message.
func (c *Chatter) SendMessage(partnerIdentity *PublicKey,
	plaintext string) (*Message, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't send message to partner with no open session")
	}

	session := c.Sessions[*partnerIdentity]

	// Check if we need to generate a new DH ratchet
	if !session.IsSender {
		// Generate new DH ratchet key
		newEphemeral := GenerateKeyPair()
		session.MyDHRatchet.Zeroize()
		session.MyDHRatchet = newEphemeral

		newRatchet := DHCombine(session.PartnerDHRatchet, &session.MyDHRatchet.PrivateKey)
		ratchetedRoot := session.RootChain.DeriveKey(ROOT_LABEL)
		session.RootChain.Zeroize()
		session.RootChain = CombineKeys(ratchetedRoot, newRatchet)
		session.SendChain.Zeroize()
		session.SendChain = session.RootChain.DeriveKey(CHAIN_LABEL)

		session.LS = session.SendCounter
		session.IsSender = true
		ratchetedRoot.Zeroize()
		newRatchet.Zeroize()
	}

	// Derive message key from send chain
	messageKey := session.SendChain.DeriveKey(KEY_LABEL)
	iv := NewIV()

	// Create message
	message := &Message{
		Sender:        &c.Identity.PublicKey,
		Receiver:      partnerIdentity,
		NextDHRatchet: &session.MyDHRatchet.PublicKey,
		Counter:       session.SendCounter,
		LastUpdate:    session.LS,
		IV:            iv,
	}

	// Encrypt

	additionalData := message.EncodeAdditionalData()
	ciphertext := messageKey.AuthenticatedEncrypt(plaintext, additionalData, iv)
	message.Ciphertext = ciphertext

	// Ratchet send chain and increment counter
	newSendChain := session.SendChain.DeriveKey(CHAIN_LABEL)
	session.SendChain.Zeroize()
	session.SendChain = newSendChain
	session.SendCounter += 1
	messageKey.Zeroize()

	return message, nil
}

func (c *Chatter) ReceiveMessage(message *Message) (string, error) {

	if _, exists := c.Sessions[*message.Sender]; !exists {
		return "", errors.New("Can't receive message from partner with no open session")
	}

	session := c.Sessions[*message.Sender]

	// Handle late/out-of-order messages (check cache first, regardless of ratchet)
	if message.Counter < session.ReceiveCounter || message.LastUpdate < session.LR {
		if key, exists := session.CachedReceiveKeys[message.Counter]; exists {
			additionalData := message.EncodeAdditionalData()
			plaintext, err := key.AuthenticatedDecrypt(message.Ciphertext, additionalData, message.IV)
			if err != nil {
				return "", err
			}
			// Remove cached key after successful decryption
			key.Zeroize()
			delete(session.CachedReceiveKeys, message.Counter)
			return plaintext, nil
		}
		return "", errors.New("Late message with no cached key or replay attack")
	}

	if message.LastUpdate == session.LR {
		tempChain := session.ReceiveChain
		tempCachedKeys := make(map[int]*SymmetricKey)
		createdChains := []*SymmetricKey{}

		for i := session.ReceiveCounter; i < message.Counter; i++ {
			messageKey := tempChain.DeriveKey(KEY_LABEL)
			tempCachedKeys[i] = messageKey
			nextChain := tempChain.DeriveKey(CHAIN_LABEL)
			// record nextChain for cleanup if we fail
			createdChains = append(createdChains, nextChain)
			// advance tempChain to the newly-created nextChain
			tempChain = nextChain
		}

		messageKey := tempChain.DeriveKey(KEY_LABEL)
		additionalData := message.EncodeAdditionalData()
		plaintext, err := messageKey.AuthenticatedDecrypt(message.Ciphertext, additionalData, message.IV)
		if err != nil {
			for _, key := range tempCachedKeys {
				key.Zeroize()
			}
			messageKey.Zeroize()
			for _, ch := range createdChains {
				if ch != nil {
					ch.Zeroize()
				}
			}
			return "", err
		}

		for i, key := range tempCachedKeys {
			session.CachedReceiveKeys[i] = key
		}
		session.ReceiveChain = tempChain.DeriveKey(CHAIN_LABEL)
		session.ReceiveCounter = message.Counter + 1

		tempChain.Zeroize()
		messageKey.Zeroize()

		return plaintext, nil
	}

	// New ratchet (partner switched to sending)
	if message.LastUpdate > session.LR {
		tempCachedKeys := make(map[int]*SymmetricKey)

		// Cache remaining messages from old receive chain (temporary)
		tempChain := session.ReceiveChain
		createdChains := []*SymmetricKey{}
		for i := session.ReceiveCounter; i < message.LastUpdate; i++ {
			messageKey := tempChain.DeriveKey(KEY_LABEL)
			tempCachedKeys[i] = messageKey
			nextChain := tempChain.DeriveKey(CHAIN_LABEL)
			// record nextChain for cleanup if we fail
			createdChains = append(createdChains, nextChain)
			// advance tempChain to the newly-created nextChain
			tempChain = nextChain
		}

		// Perform temporary DH ratchet
		newRatchet := DHCombine(message.NextDHRatchet, &session.MyDHRatchet.PrivateKey)
		ratchetedRoot := session.RootChain.DeriveKey(ROOT_LABEL)
		newRootChain := CombineKeys(ratchetedRoot, newRatchet)
		newReceiveChain := newRootChain.DeriveKey(CHAIN_LABEL)

		// Cache skipped messages in temporary new ratchet
		for i := message.LastUpdate; i < message.Counter; i++ {
			messageKey := newReceiveChain.DeriveKey(KEY_LABEL)
			tempCachedKeys[i] = messageKey
			nextChain := newReceiveChain.DeriveKey(CHAIN_LABEL)
			newReceiveChain.Zeroize()
			newReceiveChain = nextChain
		}

		// Derive key for current message
		messageKey := newReceiveChain.DeriveKey(KEY_LABEL)
		additionalData := message.EncodeAdditionalData()
		plaintext, err := messageKey.AuthenticatedDecrypt(message.Ciphertext, additionalData, message.IV)
		if err != nil {
			for _, key := range tempCachedKeys {
				key.Zeroize()
			}
			messageKey.Zeroize()
			newReceiveChain.Zeroize()
			ratchetedRoot.Zeroize()
			newRatchet.Zeroize()
			for _, ch := range createdChains {
				if ch != nil {
					ch.Zeroize()
				}
			}
			return "", err
		}

		// SUCCESS - now commit all state changes
		for i, key := range tempCachedKeys {
			session.CachedReceiveKeys[i] = key
		}
		session.RootChain.Zeroize()
		session.RootChain = newRootChain
		session.ReceiveChain.Zeroize()
		session.ReceiveChain = newReceiveChain.DeriveKey(CHAIN_LABEL)
		session.LR = message.LastUpdate
		session.ReceiveCounter = message.Counter + 1
		session.PartnerDHRatchet = message.NextDHRatchet
		session.IsSender = false
		tempChain.Zeroize()
		messageKey.Zeroize()
		newReceiveChain.Zeroize()
		ratchetedRoot.Zeroize()
		newRatchet.Zeroize()

		return plaintext, nil
	}

	return "", errors.New("Unexpected message state")
}
