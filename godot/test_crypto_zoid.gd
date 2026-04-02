extends SceneTree

## CryptoZoid GDExtension Test Script
## Run with: godot --headless --script test_crypto_zoid.gd
## (Requires CryptoZoid addon to be loaded)

func _init() -> void:
	print("=== CryptoZoid Test Suite ===")
	var passed := 0
	var failed := 0

	# Test 1: Keypair generation
	print("\n[1] generate_ed25519_keypair()")
	var crypto := CryptoZoid.new()
	var keypair: Dictionary = crypto.generate_ed25519_keypair()
	var private_key: PackedByteArray = keypair.get("private_key", PackedByteArray())
	var public_key: PackedByteArray = keypair.get("public_key", PackedByteArray())

	if private_key.size() == 32 and public_key.size() == 32:
		print("  PASS: keypair generated (32-byte private seed, 32-byte public key)")
		passed += 1
	else:
		print("  FAIL: unexpected sizes — private=%d public=%d" % [private_key.size(), public_key.size()])
		failed += 1

	# Test 2: Derive public key from private key
	print("\n[2] ed25519_public_key()")
	var derived_pub: PackedByteArray = crypto.ed25519_public_key(private_key)
	if derived_pub == public_key:
		print("  PASS: derived public key matches")
		passed += 1
	else:
		print("  FAIL: derived public key does not match generated public key")
		failed += 1

	# Test 3: Sign and verify
	print("\n[3] ed25519_sign() + ed25519_verify()")
	var message: PackedByteArray = "Hello, CryptoZoid!".to_utf8_buffer()
	var signature: PackedByteArray = crypto.ed25519_sign(private_key, message)

	if signature.size() == 64:
		print("  PASS: signature is 64 bytes")
		passed += 1
	else:
		print("  FAIL: signature size is %d (expected 64)" % signature.size())
		failed += 1

	var valid: bool = crypto.ed25519_verify(public_key, message, signature)
	if valid:
		print("  PASS: signature verified")
		passed += 1
	else:
		print("  FAIL: signature verification failed")
		failed += 1

	# Test 4: Verify rejects tampered message
	print("\n[4] ed25519_verify() rejects tampered message")
	var tampered: PackedByteArray = "Hello, CryptoZoid?".to_utf8_buffer()
	var invalid: bool = crypto.ed25519_verify(public_key, tampered, signature)
	if not invalid:
		print("  PASS: correctly rejected tampered message")
		passed += 1
	else:
		print("  FAIL: accepted tampered message (this is a security bug!)")
		failed += 1

	# Test 5: SHA-256 of "hello"
	print("\n[5] sha256_hex()")
	var hello: PackedByteArray = "hello".to_utf8_buffer()
	var hash_hex: String = crypto.sha256_hex(hello)
	var expected_hex := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if hash_hex == expected_hex:
		print("  PASS: SHA-256('hello') = %s" % hash_hex)
		passed += 1
	else:
		print("  FAIL: SHA-256('hello') = %s (expected %s)" % [hash_hex, expected_hex])
		failed += 1

	# Test 6: SHA-256 raw bytes
	print("\n[6] sha256() raw bytes")
	var hash_bytes: PackedByteArray = crypto.sha256(hello)
	if hash_bytes.size() == 32:
		print("  PASS: sha256() returns 32 bytes")
		passed += 1
	else:
		print("  FAIL: sha256() returned %d bytes" % hash_bytes.size())
		failed += 1

	# Test 7: Base64url encode/decode round-trip
	print("\n[7] base64url_encode() + base64url_decode() round-trip")
	var test_data: PackedByteArray = PackedByteArray([0, 1, 2, 255, 254, 253, 128, 64, 32])
	var encoded: String = crypto.base64url_encode(test_data)
	var decoded: PackedByteArray = crypto.base64url_decode(encoded)

	if decoded == test_data:
		print("  PASS: round-trip OK (encoded: %s)" % encoded)
		passed += 1
	else:
		print("  FAIL: round-trip mismatch")
		failed += 1

	# Test 8: No padding in base64url
	print("\n[8] base64url has no padding")
	if not encoded.contains("="):
		print("  PASS: no '=' padding in base64url output")
		passed += 1
	else:
		print("  FAIL: found '=' padding in: %s" % encoded)
		failed += 1

	# Test 9: random_bytes
	print("\n[9] random_bytes()")
	var rnd: PackedByteArray = crypto.random_bytes(32)
	if rnd.size() == 32:
		print("  PASS: random_bytes(32) returned 32 bytes")
		passed += 1
	else:
		print("  FAIL: random_bytes(32) returned %d bytes" % rnd.size())
		failed += 1

	# Test 10: random_bytes are not all zero (sanity check)
	print("\n[10] random_bytes() are not all zero")
	var all_zero := true
	for b in rnd:
		if b != 0:
			all_zero = false
			break
	if not all_zero:
		print("  PASS: random bytes contain non-zero values")
		passed += 1
	else:
		print("  FAIL: all bytes are zero — RNG may be broken")
		failed += 1

	# Summary
	print("\n=== Results: %d/%d passed ===" % [passed, passed + failed])
	if failed == 0:
		print("All tests passed! 🦞🤖")
	else:
		print("%d test(s) failed." % failed)

	crypto.free()
	quit(0 if failed == 0 else 1)
