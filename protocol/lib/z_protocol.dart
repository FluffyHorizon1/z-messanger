/// Z protocol — end-to-end encryption core for the Z messenger.
///
/// Pure Dart (no Flutter dependency) so the exact code that ships in the app
/// is testable headlessly and reusable in other Dart frontends.
library z_protocol;

export 'src/attachments.dart';
export 'src/identity.dart';
export 'src/messages.dart';
export 'src/multidevice.dart';
export 'src/relay_client.dart';
export 'src/ratchet.dart'
    show
        RatchetState,
        RatchetHeader,
        RatchetMessage,
        RatchetDecryptException,
        ratchetEncrypt,
        ratchetDecrypt,
        ratchetInitInitiator,
        ratchetInitResponder;
export 'src/session.dart';
export 'src/util.dart'
    show
        b64,
        unb64,
        b64url,
        unb64url,
        randomBytes,
        sha256Bytes,
        constantTimeEquals;
