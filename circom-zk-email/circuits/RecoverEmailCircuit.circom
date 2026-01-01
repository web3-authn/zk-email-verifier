pragma circom 2.1.5;

include "@zk-email/circuits/email-verifier.circom";

template MyCircuit(max_header_bytes, max_body_bytes, n, k, pack_size) {
    // EmailVerifier inputs (headers only)
    signal input emailHeader[max_header_bytes];
    signal input emailHeaderLength;
    signal input pubkey[k];
    signal input signature[k];

    // Subject layout (private inputs)
    // subject_start_idx: index of 'S' in "Subject: recover-<request_id> <...> ed25519:<...>"
    signal input subject_start_idx;
    signal input subject_request_id_idx;
    signal input subject_request_id_len;
    signal input subject_account_id_idx;
    signal input subject_public_key_idx;
    signal input subject_account_id_len;
    signal input subject_public_key_len;

    // From: header layout (private inputs)
    // from_start_idx: index of 'f' in "from: <...>"
    signal input from_start_idx;
    signal input from_addr_idx;
    signal input from_addr_len;

    // Date header layout (private inputs)
    // date_start_idx: index of 'd' in "date: <...>"
    signal input date_start_idx;
    signal input date_timestamp_idx;
    signal input date_timestamp_len;

    // Email Verifier
    // ignoreBodyHashCheck = 1 (only headers), masking & soft line breaks disabled
    component emailVerifier = EmailVerifier(max_header_bytes, max_body_bytes, n, k, 1, 0, 0, 0);
    emailVerifier.emailHeader <== emailHeader;
    emailVerifier.emailHeaderLength <== emailHeaderLength;
    emailVerifier.pubkey <== pubkey;
    emailVerifier.signature <== signature;

    // Enforce Subject line format:
    // "subject:recover-" + request_id + " " + accountId + " ed25519:" + publicKey
    // (header field name and spacing are canonicalized by DKIM)
    var prefix1_len = 16; // "subject:recover-"
    var prefix2_len = 8;  // "ed25519:"

    // Anchor check for Subject:
    // If subject_start_idx != 0, enforce that the two bytes immediately
    // preceding it are CRLF (`\r\n`). If subject_start_idx == 0 (happens
    // only at the very start of the header), we skip the anchor check.
    var anchor_len = 2;
    component subjectAnchor = SelectSubArray(max_header_bytes, anchor_len);
    subjectAnchor.in <== emailHeader;
    subjectAnchor.startIndex <== subject_start_idx - 2;
    subjectAnchor.length <== anchor_len;

    component subjectIsFirst = IsZero();
    subjectIsFirst.in <== subject_start_idx;

    (1 - subjectIsFirst.out) * (subjectAnchor.out[0] - 13) === 0; // '\r'
    (1 - subjectIsFirst.out) * (subjectAnchor.out[1] - 10) === 0; // '\n'

    // Check static prefix "subject:recover-" using SelectSubArray
    component subjectPrefix = SelectSubArray(max_header_bytes, prefix1_len);
    subjectPrefix.in <== emailHeader;
    subjectPrefix.startIndex <== subject_start_idx;
    subjectPrefix.length <== prefix1_len;

    subjectPrefix.out[0] === 115;  // s
    subjectPrefix.out[1] === 117;  // u
    subjectPrefix.out[2] === 98;   // b
    subjectPrefix.out[3] === 106;  // j
    subjectPrefix.out[4] === 101;  // e
    subjectPrefix.out[5] === 99;   // c
    subjectPrefix.out[6] === 116;  // t
    subjectPrefix.out[7] === 58;   // :
    subjectPrefix.out[8] === 114;  // r
    subjectPrefix.out[9] === 101;  // e
    subjectPrefix.out[10] === 99;  // c
    subjectPrefix.out[11] === 111; // o
    subjectPrefix.out[12] === 118; // v
    subjectPrefix.out[13] === 101; // e
    subjectPrefix.out[14] === 114; // r
    subjectPrefix.out[15] === 45;  // '-'

    // Sanity: request_id must start right after the fixed prefix
    subject_request_id_idx === subject_start_idx + prefix1_len;

    // After request_id, expect a space before accountId.
    var afterRequestId = subject_request_id_idx + subject_request_id_len;
    component requestDelimiter = SelectSubArray(max_header_bytes, 1);
    requestDelimiter.in <== emailHeader;
    requestDelimiter.startIndex <== afterRequestId;
    requestDelimiter.length <== 1;

    requestDelimiter.out[0] === 32; // space

    // Sanity: account_id must start right after "recover-" + request_id + " "
    subject_account_id_idx === afterRequestId + 1;

    // After accountId, expect space then "ed25519:"
    var afterAccountId = subject_account_id_idx + subject_account_id_len;

    // space after accountId using SelectSubArray
    component delimiter = SelectSubArray(max_header_bytes, 1);
    delimiter.in <== emailHeader;
    delimiter.startIndex <== afterAccountId;
    delimiter.length <== 1;
    delimiter.out[0] === 32; // space

    // "ed25519:" using SelectSubArray
    component edPrefix = SelectSubArray(max_header_bytes, prefix2_len);
    edPrefix.in <== emailHeader;
    edPrefix.startIndex <== afterAccountId + 1;
    edPrefix.length <== prefix2_len;
    edPrefix.out[0] === 101; // e
    edPrefix.out[1] === 100; // d
    edPrefix.out[2] === 50;  // 2
    edPrefix.out[3] === 53;  // 5
    edPrefix.out[4] === 53;  // 5
    edPrefix.out[5] === 49;  // 1
    edPrefix.out[6] === 57;  // 9
    edPrefix.out[7] === 58;  // :

    // Sanity: public key starts right after "ed25519:"
    subject_public_key_idx === afterAccountId + 1 + prefix2_len;

    // Pack Subject Parts from header
    var max_subject_part_len = 255;
    component requestIdPacker = PackByteSubArray(max_header_bytes, max_subject_part_len);
    requestIdPacker.in <== emailHeader;
    requestIdPacker.startIndex <== subject_request_id_idx;
    requestIdPacker.length <== subject_request_id_len;

    component accountIdPacker = PackByteSubArray(max_header_bytes, max_subject_part_len);
    accountIdPacker.in <== emailHeader;
    accountIdPacker.startIndex <== subject_account_id_idx;
    accountIdPacker.length <== subject_account_id_len;

    var max_pubkey_len = 255;
    component publicKeyPacker = PackByteSubArray(max_header_bytes, max_pubkey_len);
    publicKeyPacker.in <== emailHeader;
    publicKeyPacker.startIndex <== subject_public_key_idx;
    publicKeyPacker.length <== subject_public_key_len;

    // Anchor check for From:
    // Same as Subject: if from_start_idx != 0, enforce CRLF immediately before.
    component fromAnchor = SelectSubArray(max_header_bytes, anchor_len);
    fromAnchor.in <== emailHeader;
    fromAnchor.startIndex <== from_start_idx - 2;
    fromAnchor.length <== anchor_len;

    component fromIsFirst = IsZero();
    fromIsFirst.in <== from_start_idx;

    (1 - fromIsFirst.out) * (fromAnchor.out[0] - 13) === 0; // '\r'
    (1 - fromIsFirst.out) * (fromAnchor.out[1] - 10) === 0; // '\n'

    // From: header prefix "from:"
    var from_prefix_len = 5;
    component fromPrefix = SelectSubArray(max_header_bytes, from_prefix_len);
    fromPrefix.in <== emailHeader;
    fromPrefix.startIndex <== from_start_idx;
    fromPrefix.length <== from_prefix_len;

    fromPrefix.out[0] === 102; // f
    fromPrefix.out[1] === 114; // r
    fromPrefix.out[2] === 111; // o
    fromPrefix.out[3] === 109; // m
    fromPrefix.out[4] === 58;  // :

    // Sender binding:
    // Compute a public hash of the canonical From email, salted by account id:
    // sha256("<canonical_from>|<account_id_lower>").
    //
    // `from_email` itself stays private; only the hash bytes are exposed.
    var max_from_len = 255;
    var max_account_len = 255;
    var max_preimage_len = 512;         // max_from_len + 1 + max_account_len = 511
    var max_preimage_padded_len = 576;  // SHA-256 padded length for <= 511 bytes is <= 576

    // Range check for From: ensure no CR or LF between "from:" and the email address.
    var from_gap_max_len = 255;
    var from_gap_start = from_start_idx + from_prefix_len;
    var from_gap_len = from_addr_idx - from_gap_start;

    component fromGap = SelectSubArray(max_header_bytes, from_gap_max_len);
    fromGap.in <== emailHeader;
    fromGap.startIndex <== from_gap_start;
    fromGap.length <== from_gap_len;

    component fromNoNewline[from_gap_max_len];
    for (var i = 0; i < from_gap_max_len; i++) {
        fromNoNewline[i] = IsZero();
        // (byte - 13) * (byte - 10) must be non-zero for actual bytes; 0s (padding) are fine.
        fromNoNewline[i].in <== (fromGap.out[i] - 13) * (fromGap.out[i] - 10);
        fromNoNewline[i].out === 0;
    }

    // Range checks for lengths used in hashing.
    component fromAddrLenBits = Num2Bits(8);
    fromAddrLenBits.in <== from_addr_len;

    component accountIdLenBits = Num2Bits(8);
    accountIdLenBits.in <== subject_account_id_len;

    // Extract From email bytes (private) and lowercase ASCII A-Z.
    component fromEmailBytes = SelectSubArray(max_header_bytes, max_from_len);
    fromEmailBytes.in <== emailHeader;
    fromEmailBytes.startIndex <== from_addr_idx;
    fromEmailBytes.length <== from_addr_len;

    signal from_email_lower[max_from_len];
    component fromByteBits[max_from_len];
    component fromLt65[max_from_len];
    component fromLt91[max_from_len];
    signal fromIsGe65[max_from_len];
    signal fromIsUpper[max_from_len];
    for (var i = 0; i < max_from_len; i++) {
        // Constrain as byte and canonicalize ASCII letters.
        fromByteBits[i] = Num2Bits(8);
        fromByteBits[i].in <== fromEmailBytes.out[i];

        fromLt65[i] = LessThan(8);
        fromLt65[i].in[0] <== fromEmailBytes.out[i];
        fromLt65[i].in[1] <== 65; // 'A'

        fromLt91[i] = LessThan(8);
        fromLt91[i].in[0] <== fromEmailBytes.out[i];
        fromLt91[i].in[1] <== 91; // 'Z' + 1

        fromIsGe65[i] <== 1 - fromLt65[i].out;
        fromIsUpper[i] <== fromIsGe65[i] * fromLt91[i].out;

        from_email_lower[i] <== fromEmailBytes.out[i] + 32 * fromIsUpper[i];
    }

    // Extract Subject account_id bytes (private) and lowercase ASCII A-Z.
    component accountIdBytes = SelectSubArray(max_header_bytes, max_account_len);
    accountIdBytes.in <== emailHeader;
    accountIdBytes.startIndex <== subject_account_id_idx;
    accountIdBytes.length <== subject_account_id_len;

    signal account_id_lower[max_account_len];
    component accountByteBits[max_account_len];
    component accountLt65[max_account_len];
    component accountLt91[max_account_len];
    signal accountIsGe65[max_account_len];
    signal accountIsUpper[max_account_len];
    for (var i = 0; i < max_account_len; i++) {
        accountByteBits[i] = Num2Bits(8);
        accountByteBits[i].in <== accountIdBytes.out[i];

        accountLt65[i] = LessThan(8);
        accountLt65[i].in[0] <== accountIdBytes.out[i];
        accountLt65[i].in[1] <== 65; // 'A'

        accountLt91[i] = LessThan(8);
        accountLt91[i].in[0] <== accountIdBytes.out[i];
        accountLt91[i].in[1] <== 91; // 'Z' + 1

        accountIsGe65[i] <== 1 - accountLt65[i].out;
        accountIsUpper[i] <== accountIsGe65[i] * accountLt91[i].out;

        account_id_lower[i] <== accountIdBytes.out[i] + 32 * accountIsUpper[i];
    }

    // Build preimage bytes: <from_email_lower>|<account_id_lower>
    // using rotation-with-zero-fill shifts (VarShiftLeft) so we can concatenate with a dynamic boundary.
    signal fromVec[max_preimage_len];
    signal accountVecBase[max_preimage_len];
    signal delimBase[max_preimage_len];

    for (var i = 0; i < max_preimage_len; i++) {
        if (i < max_from_len) {
            fromVec[i] <== from_email_lower[i];
        } else {
            fromVec[i] <== 0;
        }

        if (i < max_account_len) {
            accountVecBase[i] <== account_id_lower[i];
        } else {
            accountVecBase[i] <== 0;
        }

        if (i == 0) {
            delimBase[i] <== 124; // '|'
        } else {
            delimBase[i] <== 0;
        }
    }

    // Shift account bytes right by (from_addr_len + 1) positions (rotation with zero-filled tail).
    signal accountShiftLeft;
    accountShiftLeft <== max_preimage_len - from_addr_len - 1;
    component accountShifter = VarShiftLeft(max_preimage_len, max_preimage_len);
    accountShifter.in <== accountVecBase;
    accountShifter.shift <== accountShiftLeft;

    // Shift delimiter right by from_addr_len positions; if from_addr_len == 0, keep at index 0.
    component fromLenIsZero = IsZero();
    fromLenIsZero.in <== from_addr_len;

    signal delimShiftLeft;
    delimShiftLeft <== (max_preimage_len - from_addr_len) * (1 - fromLenIsZero.out);
    component delimShifter = VarShiftLeft(max_preimage_len, max_preimage_len);
    delimShifter.in <== delimBase;
    delimShifter.shift <== delimShiftLeft;

    // Combine into full preimage (no overlaps by construction).
    signal preimage[max_preimage_len];
    for (var i = 0; i < max_preimage_len; i++) {
        preimage[i] <== fromVec[i] + delimShifter.out[i] + accountShifter.out[i];
    }

    // Message length (bytes) for standard SHA-256 padding.
    signal preimage_len;
    preimage_len <== from_addr_len + 1 + subject_account_id_len;

    // Constrain preimage_len to 0..511 (9 bits).
    component preimageLenBits = Num2Bits(9);
    preimageLenBits.in <== preimage_len;

    // Compute padded length in bytes: 64 * ceil((preimage_len + 9) / 64)
    component le55 = LessEqThan(9);
    le55.in[0] <== preimage_len;
    le55.in[1] <== 55;
    component le119 = LessEqThan(9);
    le119.in[0] <== preimage_len;
    le119.in[1] <== 119;
    component le183 = LessEqThan(9);
    le183.in[0] <== preimage_len;
    le183.in[1] <== 183;
    component le247 = LessEqThan(9);
    le247.in[0] <== preimage_len;
    le247.in[1] <== 247;
    component le311 = LessEqThan(9);
    le311.in[0] <== preimage_len;
    le311.in[1] <== 311;
    component le375 = LessEqThan(9);
    le375.in[0] <== preimage_len;
    le375.in[1] <== 375;
    component le439 = LessEqThan(9);
    le439.in[0] <== preimage_len;
    le439.in[1] <== 439;
    component le503 = LessEqThan(9);
    le503.in[0] <== preimage_len;
    le503.in[1] <== 503;

    signal isBlock1;
    signal isBlock2;
    signal isBlock3;
    signal isBlock4;
    signal isBlock5;
    signal isBlock6;
    signal isBlock7;
    signal isBlock8;
    signal isBlock9;

    isBlock1 <== le55.out;
    isBlock2 <== le119.out - le55.out;
    isBlock3 <== le183.out - le119.out;
    isBlock4 <== le247.out - le183.out;
    isBlock5 <== le311.out - le247.out;
    isBlock6 <== le375.out - le311.out;
    isBlock7 <== le439.out - le375.out;
    isBlock8 <== le503.out - le439.out;
    isBlock9 <== 1 - le503.out;

    isBlock1 + isBlock2 + isBlock3 + isBlock4 + isBlock5 + isBlock6 + isBlock7 + isBlock8 + isBlock9 === 1;

    signal numBlocks;
    numBlocks <== 1 * isBlock1
              + 2 * isBlock2
              + 3 * isBlock3
              + 4 * isBlock4
              + 5 * isBlock5
              + 6 * isBlock6
              + 7 * isBlock7
              + 8 * isBlock8
              + 9 * isBlock9;

    signal preimage_padded_len;
    preimage_padded_len <== numBlocks * 64;

    // Build SHA-256 padded message bytes (length <= 576).
    signal preimage_ext[max_preimage_padded_len];
    for (var i = 0; i < max_preimage_padded_len; i++) {
        if (i < max_preimage_len) {
            preimage_ext[i] <== preimage[i];
        } else {
            preimage_ext[i] <== 0;
        }
    }

    // Insert 0x80 at index preimage_len via rotation.
    signal oneBase[max_preimage_padded_len];
    for (var i = 0; i < max_preimage_padded_len; i++) {
        if (i == 0) {
            oneBase[i] <== 128;
        } else {
            oneBase[i] <== 0;
        }
    }

    signal shiftOne;
    shiftOne <== max_preimage_padded_len - preimage_len;
    component oneShifter = VarShiftLeft(max_preimage_padded_len, max_preimage_padded_len);
    oneShifter.in <== oneBase;
    oneShifter.shift <== shiftOne;

    // Length field (64-bit big-endian) for messages <= 511 bytes:
    // only the last two bytes can be non-zero since len_bits <= 4088.
    signal len_bits;
    len_bits <== preimage_len * 8;

    // Split len_bits into 2 bytes (hi/lo) via bit decomposition.
    component lenBitsDecomp = Num2Bits(16);
    lenBitsDecomp.in <== len_bits;

    component lenLo = Bits2Num(8);
    component lenHi = Bits2Num(8);
    for (var i = 0; i < 8; i++) {
        lenLo.in[i] <== lenBitsDecomp.out[i];
        lenHi.in[i] <== lenBitsDecomp.out[8 + i];
    }

    signal lenBase[max_preimage_padded_len];
    for (var i = 0; i < max_preimage_padded_len; i++) {
        if (i == 6) {
            lenBase[i] <== lenHi.out;
        } else if (i == 7) {
            lenBase[i] <== lenLo.out;
        } else {
            lenBase[i] <== 0;
        }
    }

    signal shiftLen;
    shiftLen <== (max_preimage_padded_len + 8) - preimage_padded_len; // 576 - (preimage_padded_len - 8)
    component lenShifter = VarShiftLeft(max_preimage_padded_len, max_preimage_padded_len);
    lenShifter.in <== lenBase;
    lenShifter.shift <== shiftLen;

    // Final padded preimage bytes.
    signal from_address_hash_preimage_padded[max_preimage_padded_len];
    for (var i = 0; i < max_preimage_padded_len; i++) {
        from_address_hash_preimage_padded[i] <== preimage_ext[i] + oneShifter.out[i] + lenShifter.out[i];
    }

    // SHA-256("<from>|<account_id>") as bits (big-endian).
    signal from_address_hash_bits[256] <== Sha256Bytes(max_preimage_padded_len)(
        from_address_hash_preimage_padded,
        preimage_padded_len
    );

    // Pack digest bits into 32 raw bytes (big-endian).
    component fromAddressHashBytes = PackBits(256, 8);
    fromAddressHashBytes.in <== from_address_hash_bits;

    // Anchor check for Date:
    // If date_start_idx != 0, enforce CRLF immediately before.
    component dateAnchor = SelectSubArray(max_header_bytes, anchor_len);
    dateAnchor.in <== emailHeader;
    dateAnchor.startIndex <== date_start_idx - 2;
    dateAnchor.length <== anchor_len;

    component dateIsFirst = IsZero();
    dateIsFirst.in <== date_start_idx;

    (1 - dateIsFirst.out) * (dateAnchor.out[0] - 13) === 0; // '\r'
    (1 - dateIsFirst.out) * (dateAnchor.out[1] - 10) === 0; // '\n'

    // Date: header prefix "date:"
    var date_prefix_len = 5;
    component datePrefix = SelectSubArray(max_header_bytes, date_prefix_len);
    datePrefix.in <== emailHeader;
    datePrefix.startIndex <== date_start_idx;
    datePrefix.length <== date_prefix_len;

    datePrefix.out[0] === 100; // d
    datePrefix.out[1] === 97;  // a
    datePrefix.out[2] === 116; // t
    datePrefix.out[3] === 101; // e
    datePrefix.out[4] === 58;  // :

    // Pack Date timestamp substring from header
    var max_date_len = 255;
    component datePacker = PackByteSubArray(max_header_bytes, max_date_len);
    datePacker.in <== emailHeader;
    datePacker.startIndex <== date_timestamp_idx;
    datePacker.length <== date_timestamp_len;

    // Outputs
    // 255 bytes / 31 bytes per signal = 9 signals
    signal output request_id_packed[9];
    request_id_packed <== requestIdPacker.out;

    signal output account_id_packed[9];
    account_id_packed <== accountIdPacker.out;

    signal output public_key_packed[9];
    public_key_packed <== publicKeyPacker.out;

    signal output from_address_hash[32];
    from_address_hash <== fromAddressHashBytes.out;

    signal output timestamp_packed[9];
    timestamp_packed <== datePacker.out;
}

// Main component
// n=121, k=17 for RSA-2048
component main { public [ pubkey, signature ] } = MyCircuit(1024, 64, 121, 17, 31);
