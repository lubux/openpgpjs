
unittests.register("Packet testing", function() {

	var armored_key =
		'-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
		'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
		'\n' +
		'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\n' +
		'YRlci72GHhlyos8YHA==\n' +
		'=KXkj\n' +
		'-----END PGP PRIVATE KEY BLOCK-----';


	var tests = [function() {

		var literal = new openpgp_packet_literal();
		literal.set_data('Hello world', openpgp_packet_literal.format.utf8);
		
		var enc = new openpgp_packet_symmetrically_encrypted();
		enc.packets.push(literal);

		var key = '12345678901234567890123456789012',
			algo = openpgp.symmetric.aes256;

		enc.encrypt(algo, key);

		var message = new openpgp_packetlist();
		message.push(enc);


		var msg2 = new openpgp_packetlist();
		msg2.read(message.write());

		msg2[0].decrypt(algo, key);

		return new test_result('Symmetrically encrypted packet', 
			msg2[0].packets[0].data == literal.data);

	}, function() {
		var key = '12345678901234567890123456789012',
			algo = openpgp.symmetric.aes256;

		var literal = new openpgp_packet_literal(),
			enc = new openpgp_packet_sym_encrypted_integrity_protected(),
			msg = new openpgp_packetlist();

		literal.set_data('Hello world!', openpgp_packet_literal.format.utf8);
		enc.packets.push(literal);
		enc.encrypt(algo, key);
		msg.push(enc);
		


		var msg2 = new openpgp_packetlist();
		msg2.read(msg.write());

		msg2[0].decrypt(algo, key);

		return new test_result('Sym. encrypted integrity protected packet', 
			msg2[0].packets[0].data == literal.data);
	
	}, function() {
			
		var msg = 
			'-----BEGIN PGP MESSAGE-----\n' +
			'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
			'\n' +
			'jA0ECQMCpo7I8WqsebTJ0koBmm6/oqdHXJU9aPe+Po+nk/k4/PZrLmlXwz2lhqBg\n' +
			'GAlY9rxVStLBrg0Hn+5gkhyHI9B85rM1BEYXQ8pP5CSFuTwbJ3O2s67dzQ==\n' +
			'=VZ0/\n' +
			'-----END PGP MESSAGE-----';



		var msgbytes = openpgp_encoding_dearmor(msg).openpgp;

		var parsed = new openpgp_packetlist();
		parsed.read(msgbytes);

		parsed[0].decrypt('test');

		var key = parsed[0].key;
		parsed[1].decrypt(parsed[0].algorithm, key);
		var compressed = parsed[1].packets[0];

		var result = compressed.packets[0].data;

		return new test_result('Sym encrypted session key with a compressed packet',
			result == 'Hello world!\n');

	}, function() {
	
		var rsa = new RSA(),
			key = rsa.generate(512, "10001")


		var key = [
			[key.d, key.p, key.q, key.u],
			[key.n, key.ee]];

		key = key.map(function(k) {
			return k.map(function(bn) {
				var mpi = new openpgp_type_mpi();
				mpi.fromBigInteger(bn);
				return mpi;
				});
		});

		var mpi = new openpgp_type_mpi();
		mpi.fromBigInteger(key[0][1].data);
		mpi.read(mpi.write());

		var enc = new openpgp_packet_public_key_encrypted_session_key(),
			msg = new openpgp_packetlist(),
			msg2 = new openpgp_packetlist();

		enc.symmetric_key = '12345678901234567890123456789012';
		enc.public_key_algorithm = openpgp.publickey.rsa_encrypt;
		enc.symmetric_algorithm = openpgp.symmetric.aes256;
		enc.public_key_id.bytes = '12345678';
		enc.encrypt(key[1]);

		msg.push(enc);

		msg2.read(msg.write());

		msg2[0].decrypt(key[1], key[0]);

		return new test_result('Public key encrypted symmetric key packet', 
			msg2[0].symmetric_key == enc.symmetric_key &&
			msg2[0].symmetric_algorithm == enc.symmetric_algorithm);
	}, function() {
		var armored_key = 
			'-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
			'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
			'\n' +
			'lQHYBFF33iMBBAC9YfOYahJlWrVj2J1TjQiZLunWljI4G9e6ARTyD99nfOkV3swh\n' +
			'0WaOse4Utj7BfTqdYcoezhCaQpuExUupKWZqmduBcwSmEBfNu1XyKcxlDQuuk0Vk\n' +
			'viGC3kFRce/cJaKVFSRU8V5zPgt6KQNv/wNz7ydEisaSoNbk51vQt5oGfwARAQAB\n' +
			'AAP5AVL8xWMuKgLj9g7/wftMH+jO7vhAxje2W3Y+8r8TnOSn0536lQvzl/eQyeLC\n' +
			'VK2k3+7+trgO7I4KuXCXZqgAbEi3niDYXDaCJ+8gdR9qvPM2gi9NM71TGXZvGE0w\n' +
			'X8gIZfqLTQWKm9TIS/3tdrth4nwhiye0ASychOboIiN6VIECAMbCQ4/noxGV6yTK\n' +
			'VezsGSz+iCMxz2lV270/Ac2C5WPk+OlxXloxUXeEkGIr6Xkmhhpceed2KL41UC8Y\n' +
			'w5ttGIECAPPsahniKGyqp9CHy6W0B83yhhcIbmLlaVG2ftKyUEDxIggzOlXuVrue\n' +
			'z9XRd6wFqwDd1QMFW0uUyHPDCIFPnv8CAJaDFSZutuWdWMt15NZXjfgRgfJuDrtv\n' +
			'E7yFY/p0el8lCihOT8WoHbTn1PbCYMzNBc0IhHaZKAtA2pjkE+wzz9ClP7QbR2Vv\n' +
			'cmdlIDxnZW9yZ2VAZXhhbXBsZS5jb20+iLkEEwECACMFAlF33iMCGwMHCwkIBwMC\n' +
			'AQYVCAIJCgsEFgIDAQIeAQIXgAAKCRBcqs36fwJCXRbvA/9LPiK6WFKcFoNBnLEJ\n' +
			'mS/CNkL8yTpkslpCP6+TwJMc8uXqwYl9/PW2+CwmzZjs6JsvTzMcR/ZbfZJuSW6Y\n' +
			'EsLNejsSpgcY9aiewGtE+53e5oKYnlmVMTWOPywciIgMvXlzdGhxcwqJ8u0hT+ug\n' +
			'9CjcAfuX9yw85LwXtdGwNh7J8Q==\n' +
			'=lKiS\n' +
			'-----END PGP PRIVATE KEY BLOCK-----';

		key = new openpgp_packetlist();
		key.read(openpgp_encoding_dearmor(armored_key).openpgp);
		key = key[0];

		var enc = new openpgp_packet_public_key_encrypted_session_key(),
			secret = '12345678901234567890123456789012';

		enc.symmetric_key = secret;
		enc.public_key_algorithm = openpgp.publickey.rsa_encrypt;
		enc.symmetric_algorithm = openpgp.symmetric.aes256;
		enc.public_key_id.bytes = '12345678';

		enc.encrypt(key.public_key.mpi);

		enc.decrypt(key.public_key.mpi, key.mpi);

		return new test_result('Secret key packet (reading, unencrpted)',
			enc.symmetric_key == secret);
	}, function() {

		var armored_key =
			'-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
			'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
			'\n' +
			'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\n' +
			'=FSwA\n' +
			'-----END PGP PRIVATE KEY BLOCK-----';

		var armored_msg = 
			'-----BEGIN PGP MESSAGE-----\n' +
			'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
			'\n' +
			'hIwDFYET+7bfx/ABA/95Uc9942Tg8oqpO0vEu2eSKwPALM3a0DrVdAiFOIK/dJmZ\n' +
			'YrtPRw3EEwHZjl6CO9RD+95iE27tPbsICw1K43gofSV/wWsPO6vvs3eftQYHSxxa\n' +
			'IQbTPImiRaJ73Mf7iM3CNtQM4iUBsx1HnUGl+rtD0nz3fLm6i3CjwiNQWW42I9JH\n' +
			'AWv8EvvpxZ8X2ClFfSW3UVBoROHe9CAWHM/40nGutAZK8MIgmUI4xqkLFBbqqTyx\n' +
			'/cDSC4Q+sv65UX4urbfc7uJuk1Cpj54=\n' +
			'=iSaK\n' +
			'-----END PGP MESSAGE-----';


		var key = new openpgp_packetlist();
		key.read(openpgp_encoding_dearmor(armored_key).openpgp);
		key = key[3];

		var msg = new openpgp_packetlist();
		msg.read(openpgp_encoding_dearmor(armored_msg).openpgp);

		msg[0].decrypt(key.public_key.mpi, key.mpi);
		msg[1].decrypt(msg[0].symmetric_algorithm, msg[0].symmetric_key);

		var text = msg[1].packets[0].packets[0].data;


		return new test_result('Public key encrypted packet (reading, GPG)',
			text == 'Hello world!');
	}, function() {

		var passphrase = 'hello',
			algo = openpgp.symmetric.aes256;

		var literal = new openpgp_packet_literal(),
			key_enc = new openpgp_packet_sym_encrypted_session_key(),
			enc = new openpgp_packet_sym_encrypted_integrity_protected(),
			msg = new openpgp_packetlist();


		key_enc.algorithm = algo;
		key_enc.decrypt(passphrase);
		var key = key_enc.key;

		literal.set_data('Hello world!', openpgp_packet_literal.format.utf8);
		enc.packets.push(literal);
		enc.encrypt(algo, key);

		msg.push(key_enc);
		msg.push(enc);

		var msg2 = new openpgp_packetlist();
		msg2.read(msg.write());

		msg2[0].decrypt(passphrase);
		var key2 = msg2[0].key;
		msg2[1].decrypt(msg2[0].algorithm, key2);


		return new test_result('Sym encrypted session key reading/writing', 
			msg2[1].packets[0].data == literal.data);
	
	}, function() {
		var armored_msg = 
			'-----BEGIN PGP MESSAGE-----\n' +
			'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
			'\n' +
			'hIwD95D9aHS5fxEBA/98CwH54XZmwobOmHUcvWcDDQysBEC4uf7wASiGcRbejDaO\n' +
			'aJqcrK/3k8sBQMO7yOhvrCRqqpGDqnmx7IaaKLnZS7nYAZoHEsK9UyG0hDa8Cfbo\n' +
			'CP4xZVcgIvIfAW/in1LeT2td0QcQNbeewBmPea+vQEEvRgIP10tlE7MK8Ay48dJH\n' +
			'AagMgNYg7MBUjpuOCVrjM1pWja8uzbULfYhTq3IJ8H3QhbdT+k9khY9f0aJPEeYi\n' +
			'dVv6DK9uviMGc/DsVCw5K8lQRLlkcHc=\n' +
			'=pR+C\n' +
			'-----END PGP MESSAGE-----';

		var key = new openpgp_packetlist();
		key.read(openpgp_encoding_dearmor(armored_key).openpgp);
		key = key[3];
		key.decrypt('test');

		var msg = new openpgp_packetlist();
		msg.read(openpgp_encoding_dearmor(armored_msg).openpgp);

		msg[0].decrypt(key.public_key.mpi, key.mpi);
		msg[1].decrypt(msg[0].symmetric_algorithm, msg[0].symmetric_key);

		var text = msg[1].packets[0].packets[0].data;



		return new test_result('Secret key encryption/decryption test',
			text == 'Hello world!');
	}, function() {
	

		var key = new openpgp_packetlist();
		key.read(openpgp_encoding_dearmor(armored_key).openpgp);


		var verified = key[2].verify(key[0].public_key,
			{
				userid: key[1],
				key: key[0].public_key
			});

		verified = verified && key[4].verify(key[0].public_key,
			{
				key: key[0].public_key,
				bind: key[3].public_key
			})


		return new test_result('Secret key reading with signature verification.',
			verified == true);
	}, function() {

		var armored_msg = 
			'-----BEGIN PGP MESSAGE-----\n' +
			'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
			'\n' +
			'hIwD95D9aHS5fxEBA/4/X4myvH+jB1HYNeZvdK+WsBNDMfLsBGOf205Rxr3vSob/\n' +
			'A09boj8/9lFaipqu+AEdQKEjCB8sZ+OY0WiQPEPpuhG+mVqDqEiPFkdpcqNtS0VV\n' +
			'pwqplHo6QnH2MHfxprZHYuwcEC9ynJCxJ6kSCD8Xs99h+PjxNNw7NhMjkF+N69LA\n' +
			'NwGPtbLx2/r2nR4gO8gV92A2RQCOwPP7ZV+6fXgWIs+mhyCHFP3xUP5DaFCNM8mo\n' +
			'PN97i659ucxF6IbOoK56FEaUbOPTD6xdyhWamxKfMsIb0UJgVUNhGaq+VlvOJxaB\n' +
			'iRcnY5UxsypKgtqfcKIseb21MIo4vcNdogyxBIDlAO472Zfxn0udzr6W2aQ77+NK\n' +
			'FE1O0kCXS+DTFOYYVD7X8rXGSglQsdXJmHd89sdYFQkO7D7bOLdRJuXgdgH2czCs\n' +
			'UBGuHZzsGbTdyKvpVBuS3rnyHHBk6oCnsm1Nl7eLs64VkZUxjEUbq5pb4dlr1pw2\n' +
			'ztpmpAnRcmM=\n' +
			'=htrB\n' +
			'-----END PGP MESSAGE-----'

		var key = new openpgp_packetlist();
		key.read(openpgp_encoding_dearmor(armored_key).openpgp);
		key[3].decrypt('test')

		var msg = new openpgp_packetlist();
		msg.read(openpgp_encoding_dearmor(armored_msg).openpgp);


		msg[0].decrypt(key[3].public_key.mpi, key[3].mpi);
		msg[1].decrypt(msg[0].symmetric_algorithm, msg[0].symmetric_key);

		var payload = msg[1].packets[0].packets



		var verified = payload[2].verify(key[0].public_key,
			{
				literal: payload[1]
			});



		return new test_result('Reading a signed, encrypted message.',
			verified == true);
	}, function() {
		var key = new openpgp_packetlist();
		key.push(new openpgp_packet_secret_key);

		var rsa = new RSA(),
			mpi = rsa.generate(512, "10001")


		var mpi = [
			[mpi.d, mpi.p, mpi.q, mpi.u],
			[mpi.n, mpi.ee]];

		mpi = mpi.map(function(k) {
			return k.map(function(bn) {
				var mpi = new openpgp_type_mpi();
				mpi.fromBigInteger(bn);
				return mpi;
				});
		});

		key[0].public_key.mpi = mpi[1];
		key[0].mpi = mpi[0];

		key[0].encrypt('hello');

		var raw = key.write();

		var key2 = new openpgp_packetlist();
		key2.read(raw);
		key2[0].decrypt('hello');
	
	
		return new test_result('Writing and encryptio of a secret key packet.',
			key[0].mpi.toString() == key2[0].mpi.toString());
	}];



	tests.reverse();

	var results = [];

	for(var i in tests) {
		results.push(tests[i]());
	}
	
	
	return results;
});
