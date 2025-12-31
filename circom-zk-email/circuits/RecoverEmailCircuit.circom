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

    // Pack From email address from header
    var max_from_len = 255;
    component fromEmailPacker = PackByteSubArray(max_header_bytes, max_from_len);
    fromEmailPacker.in <== emailHeader;
    fromEmailPacker.startIndex <== from_addr_idx;
    fromEmailPacker.length <== from_addr_len;

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

    signal output from_email_packed[9];
    from_email_packed <== fromEmailPacker.out;

    signal output timestamp_packed[9];
    timestamp_packed <== datePacker.out;
}

// Main component
// n=121, k=17 for RSA-2048
component main { public [ pubkey, signature ] } = MyCircuit(1024, 64, 121, 17, 31);
