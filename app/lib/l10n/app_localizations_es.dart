// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Spanish Castilian (`es`).
class AppLocalizationsEs extends AppLocalizations {
  AppLocalizationsEs([String locale = 'es']) : super(locale);

  @override
  String get unlockTitle => 'Desbloquear';

  @override
  String get unlockPassphraseLabel => 'Frase de contraseña';

  @override
  String get unlockPrompt =>
      'Introduce tu frase de contraseña para desbloquear este dispositivo.';

  @override
  String get unlockShowPassphrase => 'Mostrar la frase de contraseña';

  @override
  String get unlockHidePassphrase => 'Ocultar la frase de contraseña';

  @override
  String get unlockUseBiometrics => 'Usar huella o rostro';

  @override
  String get unlockFootnote =>
      'Tu frase de contraseña desbloquea la bóveda cifrada SOLO en este dispositivo. Nunca se envía a ningún sitio y no hay forma de recuperarla: si la olvidas, restaura tu identidad desde una copia .zid.';

  @override
  String get lockedTitle => 'Bloqueado';

  @override
  String get lockUnlock => 'Desbloquear';

  @override
  String get lockWaiting => 'Esperando…';

  @override
  String get lockUsePassphraseInstead => 'Usar la frase de contraseña';

  @override
  String get lockUnlockWithPassphrase =>
      'Desbloquear con la frase de contraseña';

  @override
  String get lockCancelled => 'Desbloqueo cancelado.';

  @override
  String get lockCouldNotVerify =>
      'No se pudo verificar. Inténtalo de nuevo o usa tu frase de contraseña.';

  @override
  String get lockIncorrectPassphrase =>
      'Frase de contraseña incorrecta. Inténtalo de nuevo.';

  @override
  String get lockNoBiometrics =>
      'Este dispositivo no tiene huella, rostro ni PIN disponibles.';

  @override
  String get voicePlay => 'Reproducir nota de voz';

  @override
  String get voicePause => 'Pausar nota de voz';

  @override
  String get voiceNoPlayback =>
      'La reproducción no está disponible en este dispositivo; guarda el archivo en su lugar.';

  @override
  String get searchHint => 'Buscar mensajes…';

  @override
  String get searchClear => 'Borrar búsqueda';

  @override
  String get searchIntro =>
      'Busca en tus mensajes. Todo se descifra en este dispositivo solo para la búsqueda; nada sale de él.';

  @override
  String searchNoResults(String query) {
    return 'Ningún mensaje coincide con “$query”.';
  }

  @override
  String get searchYouPrefix => 'Tú: ';

  @override
  String searchSenderPrefix(String name) {
    return '$name: ';
  }

  @override
  String get homeSearch => 'Buscar mensajes';

  @override
  String get homeNewGroup => 'Nuevo grupo';

  @override
  String get homeSettings => 'Ajustes';

  @override
  String get homeAddContact => 'Añadir contacto';

  @override
  String get relayLinked => 'relay enlazado';

  @override
  String get relayLinking => 'enlazando…';

  @override
  String get relayOffline => 'sin conexión';

  @override
  String get homeEmptyTitle => 'Aún no hay conversaciones';

  @override
  String get homeEmptyBody =>
      'Intercambia códigos de contacto en persona o por un canal de confianza; después, cada mensaje va cifrado de extremo a extremo y se guarda solo en vuestros dos dispositivos.';

  @override
  String get chatPreviewEmpty => 'Saluda: la línea está cifrada.';

  @override
  String chatPreviewSender(String name, String body) {
    return '$name: $body';
  }

  @override
  String get dismiss => 'Descartar';

  @override
  String contactAdded(String name) {
    return '$name añadido. Comparad los números de seguridad cuando podáis.';
  }

  @override
  String get addMyCode => 'MI CÓDIGO';

  @override
  String get addPaste => 'PEGAR';

  @override
  String get addScan => 'ESCANEAR';

  @override
  String get addMyCodeHelp =>
      'Pide a tu contacto que escanee este código QR, o envíale el código de texto por un canal de confianza. Los códigos contienen solo claves PÚBLICAS.';

  @override
  String get addCopyCode => 'Copiar código';

  @override
  String get addCodeCopied => 'Código copiado';

  @override
  String get addTheirCode => 'Su código de contacto';

  @override
  String get addNameOverride => 'Nombre (opcional: sustituye al suyo)';

  @override
  String get addVerifyAndAdd => 'Verificar y añadir';

  @override
  String get addSignatureNote =>
      'La firma del código se comprueba antes de añadir el contacto; un código manipulado se rechaza.';

  @override
  String get addScanPrompt => 'Apunta la cámara a su código Z.';

  @override
  String chatPreviewFile(String name) {
    return '📎 $name';
  }

  @override
  String get onbEnterRelayFirst => 'Introduce primero la dirección del relay.';

  @override
  String get onbRelayReachable => 'Conectado: el relay responde.';

  @override
  String get onbPickName =>
      'Elige un nombre para mostrar (solo tus contactos lo verán).';

  @override
  String get onbChooseBackup => 'Elige tu copia de seguridad de Z';

  @override
  String get onbNotABackup => 'Ese archivo no es una copia de seguridad de Z.';

  @override
  String get onbRestoreFailed =>
      'La restauración falló: secreto incorrecto o archivo dañado.';

  @override
  String get onbRecoveryCode => 'Código de recuperación';

  @override
  String get onbRecoveryCodeHelp =>
      'El código de 25 caracteres que guardaste al crear esta copia.';

  @override
  String get cancel => 'Cancelar';

  @override
  String get onbRestore => 'Restaurar';

  @override
  String get onbBackupPassphrase => 'Frase de contraseña de la copia';

  @override
  String get passphrase => 'Frase de contraseña';

  @override
  String get unlock => 'Desbloquear';

  @override
  String get onbDisplayName => 'Nombre para mostrar';

  @override
  String get onbDisplayNameHelp =>
      'Se comparte solo dentro de tu código de contacto cifrado';

  @override
  String get onbRelayAddress => 'Dirección del relay (desarrollador)';

  @override
  String get onbRelayHelp =>
      'Relay personalizado o autoalojado. Déjalo como está para usar el relay predeterminado de zmessengers.com.';

  @override
  String get onbTesting => 'Probando…';

  @override
  String get onbTestConnection => 'Probar conexión';

  @override
  String get onbCreateIdentity => 'Crear mi identidad';

  @override
  String get onbRestoreFromBackup => 'Restaurar desde una copia de seguridad';

  @override
  String get onbLinkExisting => 'Vincular a una cuenta existente';

  @override
  String get onbHideDevOptions => 'Ocultar opciones de desarrollador';

  @override
  String get onbDevOptions => 'Opciones de desarrollador';

  @override
  String get onbIdentityNote =>
      'Tu identidad es un par de claves criptográficas generado en este dispositivo. Nunca sale de él sin cifrar.';

  @override
  String get grpNeedNameAndMember =>
      'Elige un nombre de grupo y al menos un miembro.';

  @override
  String grpCreateFailed(String error) {
    return 'No se pudo crear: $error';
  }

  @override
  String get grpNew => 'Nuevo grupo';

  @override
  String get grpName => 'Nombre del grupo';

  @override
  String get grpNameHelp =>
      'Los miembros ven este nombre. Los mensajes se cifran de extremo a extremo para cada miembro por separado.';

  @override
  String get grpAddContactsFirst => 'Añade primero algunos contactos.';

  @override
  String grpCreateWithCount(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: 'Crear grupo ($count miembros)',
      one: 'Crear grupo (1 miembro)',
    );
    return '$_temp0';
  }

  @override
  String get grpAddMembers => 'Añadir miembros';

  @override
  String get add => 'Añadir';

  @override
  String get grpLeaveTitle => '¿Salir de este grupo?';

  @override
  String get grpLeaveBody =>
      'Dejarás de recibir sus mensajes. Tu copia del historial se queda en este dispositivo.';

  @override
  String get grpLeave => 'Salir';

  @override
  String get grpRemoved => 'Grupo eliminado';

  @override
  String get grpNoLongerIn => 'Ya no estás en este grupo';

  @override
  String grpMemberCount(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other:
          '$count miembros · cada mensaje se cifra de extremo a extremo para cada miembro',
      one:
          '1 miembro · cada mensaje se cifra de extremo a extremo para cada miembro',
    );
    return '$_temp0';
  }

  @override
  String get grpYouAdmin => 'Tú (administrador)';

  @override
  String get grpYou => 'Tú';

  @override
  String get grpUnknown => 'Desconocido';

  @override
  String get grpAdmin => 'administrador';

  @override
  String get grpRemoveFromGroup => 'Quitar del grupo';

  @override
  String get grpLeaveGroup => 'Salir del grupo';

  @override
  String get grpFootnote =>
      'Los grupos no existen en ningún servidor: el relay nunca conoce el nombre del grupo ni la lista de miembros. Cada mensaje se envía como copias separadas cifradas de extremo a extremo por vuestros canales 1:1 verificados.';

  @override
  String onbRelayUnreachableAt(String url) {
    return 'No se pudo contactar con un relay en $url.\nComprueba la dirección y que aparezca como activo en el panel de tu proveedor.';
  }

  @override
  String get linkCompareTitle => 'Compara el código de seguridad';

  @override
  String get linkCompareBody =>
      'Este mismo código debe aparecer en AMBOS dispositivos:';

  @override
  String get linkCompareWarn =>
      'Si son distintos, cancela: puede que alguien esté interceptando la vinculación.';

  @override
  String get linkTheyDiffer => 'Son distintos: cancelar';

  @override
  String get linkTheyMatch => 'Coinciden';

  @override
  String get linkDone =>
      'Dispositivo vinculado. Ya lleva tu cuenta y tus contactos.';

  @override
  String get linkCancelled => 'Vinculación cancelada.';

  @override
  String linkFailed(String error) {
    return 'La vinculación falló: $error';
  }

  @override
  String get linkADevice => 'Vincular un dispositivo';

  @override
  String get linkHostHelp =>
      'En el dispositivo que quieres añadir, instala Z y elige «Vincular a una cuenta existente». Mostrará un código de emparejamiento: introdúcelo aquí.';

  @override
  String get linkPairingCode => 'Código de emparejamiento';

  @override
  String get linkDeviceAction => 'Vincular dispositivo';

  @override
  String get linkSyncNote =>
      'La sincronización en vivo de mensajes entre tus dispositivos llegará en una actualización posterior; la vinculación establece ahora la conexión verificada y de confianza.';

  @override
  String get linkToAccount => 'Vincular a una cuenta';

  @override
  String get linkJoinHelp =>
      'En tu dispositivo actual, abre Ajustes → Dispositivos vinculados → «Vincular un dispositivo» e introduce el código de abajo.';

  @override
  String get copyCode => 'Copiar código';

  @override
  String get relayAddressDev => 'Dirección del relay (desarrollador)';

  @override
  String get relayHelpLink =>
      'Relay personalizado o autoalojado. Déjalo como está para usar el relay predeterminado de zmessengers.com.';

  @override
  String get hideDevOptions => 'Ocultar opciones de desarrollador';

  @override
  String get devOptions => 'Opciones de desarrollador';

  @override
  String get linkStart => 'Empezar la vinculación';

  @override
  String get linkRevokeTitle => '¿Revocar este dispositivo?';

  @override
  String linkRevokeBody(String device) {
    return 'Los mensajes dejarán de sincronizarse con «$device» y tus contactos dejarán de entregarle mensajes. No se puede deshacer: para usar ese dispositivo de nuevo tendrías que vincularlo desde cero.';
  }

  @override
  String get revoke => 'Revocar';

  @override
  String get linkedDevices => 'Dispositivos vinculados';

  @override
  String get linkNoneYet => 'Aún no hay otros dispositivos vinculados.';

  @override
  String get linkNotRoot =>
      'Este es un dispositivo vinculado. Añadir o revocar dispositivos se hace desde tu dispositivo principal, el que creó la cuenta.';

  @override
  String get linkRevokeNote =>
      'Cada dispositivo tiene sus propias claves. Revocar uno vuelve a firmar tu lista de dispositivos, así que tus contactos dejan de confiar en él de inmediato.';

  @override
  String get linkThisDevice => 'Este dispositivo';

  @override
  String linkKeyFingerprint(String fingerprint) {
    return 'Clave $fingerprint…';
  }

  @override
  String get linkRevokeDevice => 'Revocar dispositivo';

  @override
  String get backupTitle => 'Copia de seguridad';

  @override
  String get backupNoneYet => 'Aún no hay copia de seguridad';

  @override
  String backupLastTaken(String when) {
    return 'Última copia $when';
  }

  @override
  String get backupNoneBody =>
      'Tus mensajes viven solo en este dispositivo. Si lo pierdes, se pierden: no hay copia en ningún servidor.';

  @override
  String backupExistsBody(String size) {
    return '$size · guardada en este dispositivo. Guarda una copia en otro sitio para que un teléfono perdido no se la lleve consigo.';
  }

  @override
  String get backupWorking => 'Trabajando…';

  @override
  String get backupCreate => 'Crear una copia de seguridad';

  @override
  String get backupCreateHelp =>
      'Todos los mensajes, contactos, grupos y adjuntos, cifrados con un código de recuperación que solo tú tienes.';

  @override
  String get backupSaveCopy => 'Guardar una copia…';

  @override
  String get backupSaveCopyHelp =>
      'Pon la última copia de seguridad en algún lugar fuera de este dispositivo.';

  @override
  String get backupAuto => 'Copia automática';

  @override
  String backupAutoOnHelp(int days) {
    return 'Cada $days días, con el código de recuperación que guardaste. Ese código se conserva en este dispositivo para hacerlo posible.';
  }

  @override
  String get backupAutoOffHelp =>
      'Desactivada. Al activarla, tu código de recuperación se guarda en este dispositivo para que la copia pueda hacerse sin ti.';

  @override
  String get backupFootnote =>
      'Una copia de seguridad restaura tu historial en un dispositivo nuevo. No restaura tus conversaciones activas: estas vuelven a negociar sus claves por sí solas la primera vez que escribes a alguien, y la otra persona no nota nada raro.\n\nLa copia nunca pasa por el relay. Se cifra aquí, en este dispositivo, y solo el código de recuperación la abre. Si pierdes el código, nadie podrá abrir el archivo: no hay ninguna vía del lado del servidor, y esa es la idea.';

  @override
  String get backupPreparing => 'Preparando…';

  @override
  String get backupPackingMessages => 'Empaquetando mensajes…';

  @override
  String get backupPackingAttachments => 'Empaquetando adjuntos…';

  @override
  String get backupFinishing => 'Terminando…';

  @override
  String get backupCreated =>
      'Copia de seguridad creada. Guarda una copia en un lugar seguro.';

  @override
  String backupFailed(String error) {
    return 'La copia de seguridad falló: $error';
  }

  @override
  String get backupAutoOff =>
      'Copia automática desactivada. El código guardado se ha borrado.';

  @override
  String get backupAutoOn => 'Z hará una copia cada 7 días con ese código.';

  @override
  String get backupCopySaved => 'Copia guardada.';

  @override
  String backupTooLargeForPicker(String name) {
    return 'Esa copia es demasiado grande para el selector de archivos de este dispositivo. Sigue guardada en la app como $name.';
  }

  @override
  String backupSaveFailed(String error) {
    return 'No se pudo guardar: $error';
  }

  @override
  String sizeKb(String kb) {
    return '$kb KB';
  }

  @override
  String sizeMb(String mb) {
    return '$mb MB';
  }

  @override
  String get timeJustNow => 'ahora mismo';

  @override
  String timeMinutesAgo(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: 'hace $count min',
      one: 'hace 1 min',
    );
    return '$_temp0';
  }

  @override
  String timeHoursAgo(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: 'hace $count h',
      one: 'hace 1 h',
    );
    return '$_temp0';
  }

  @override
  String get timeYesterday => 'ayer';

  @override
  String timeDaysAgo(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: 'hace $count días',
    );
    return '$_temp0';
  }

  @override
  String get backupCodeTitle => 'Tu código de recuperación';

  @override
  String get backupCodeWriteDown =>
      'Apúntalo y guárdalo en un lugar separado del propio archivo de copia. Es lo único que abre la copia de seguridad.';

  @override
  String get backupCodeNobodyCan =>
      'Nadie puede recuperarlo por ti: ni nosotros, ni el relay, ni con una orden judicial. Es deliberado, y es también la razón por la que a nadie se le puede obligar a entregar tus mensajes.';

  @override
  String get copy => 'Copiar';

  @override
  String get codeCopied => 'Código copiado';

  @override
  String get backupCodeWritten => 'Ya lo he apuntado';

  @override
  String get backupWrongCode => 'Es un código válido, pero no es este.';

  @override
  String get back => 'Atrás';

  @override
  String get confirm => 'Confirmar';

  @override
  String get backupConfirmTitle => 'Escríbelo de nuevo';

  @override
  String get backupConfirmBody =>
      'Así sabemos que está bien apuntado. No importan las mayúsculas, los espacios ni los guiones.';

  @override
  String get backupAskCodeTitle => 'Tu código de recuperación';

  @override
  String get backupAskCodeBody =>
      'Escribe el código que guardaste. Se conserva en este dispositivo para que la copia pueda hacerse sola; cualquiera que ya pueda abrir esta app podría entonces abrir también tus archivos de copia.';

  @override
  String get backupAskCodeTurnOn => 'Activar';

  @override
  String get save => 'Guardar';

  @override
  String get delete => 'Eliminar';

  @override
  String get ciContactRemoved => 'Contacto eliminado';

  @override
  String ciRoutingId(String id) {
    return 'id de enrutamiento: $id…';
  }

  @override
  String ciAddedOnDevice(String device) {
    return 'Añadido en $device';
  }

  @override
  String get ciAddedOnDeviceBody =>
      'Este contacto llegó desde otro de tus dispositivos, así que aquí no se escaneó ningún código. Compara el número de seguridad de abajo antes de fiarte de él.';

  @override
  String get ciPqSigMissing => 'Nunca llegó una firma poscuántica';

  @override
  String get ciPqRefused => 'Clave poscuántica rechazada';

  @override
  String ciPqRefusedBody(String name) {
    return 'Llegó una clave poscuántica de $name que no coincide con el código que escaneaste, así que se rechazó y su identidad NO se actualizó. O algo falla en su lado, o alguien está sustituyendo claves. Compara el número de abajo antes de confiar en este chat.';
  }

  @override
  String get ciSafetyNumber => 'Número de seguridad';

  @override
  String get ciSafetyCompare =>
      'Compara estos 60 dígitos con los de su dispositivo (en persona o en una llamada de confianza). Si coinciden, nadie está entre vosotros, ni siquiera el relay.';

  @override
  String get ciDevListHybrid =>
      'Su lista de dispositivos también está firmada de forma poscuántica, así que el conjunto de dispositivos al que envías no puede falsificarse ni reducirse en silencio.';

  @override
  String get ciDevListClassical =>
      'Su lista de dispositivos está firmada solo de forma clásica. Hoy es correcto; la firma poscuántica viaja por separado y puede que aún no haya llegado.';

  @override
  String get ciRename => 'Renombrar';

  @override
  String get ciRenameContact => 'Renombrar contacto';

  @override
  String get ciResetSession => 'Restablecer la sesión segura';

  @override
  String get ciResetSessionHelp =>
      'Inicia una sesión de cifrado nueva (útil si los mensajes dejan de descifrarse)';

  @override
  String get ciResetSessionDone => 'Sesión segura restablecida';

  @override
  String get ciDeleteContact => 'Eliminar contacto y todos los mensajes';

  @override
  String get ciDeleteTitle => '¿Eliminar todo?';

  @override
  String get ciDeleteBody =>
      'Esto borra el contacto, todos los mensajes y todos los adjuntos de ESTE dispositivo. No hay copia en ningún servidor desde la que restaurar; esa es la idea.';

  @override
  String get ciBlurbClassical =>
      'Esta identidad está firmada con Ed25519. Su app no ha publicado una clave poscuántica, así que no hay nada más que comprobar.';

  @override
  String get ciBlurbPending =>
      'El código que escaneaste prometía una clave poscuántica que aún no ha llegado. Cuando llegue, este número cambiará UNA vez: es la actualización, no una manipulación, y se te pedirá que lo compares de nuevo. Hasta entonces solo está cubierta la mitad Ed25519.';

  @override
  String get ciBlurbHybrid =>
      'Cubre ambas mitades de ambas identidades: Ed25519 y ML-DSA-65. La clave poscuántica llegó por la sesión cifrada y coincidió con el compromiso del código que escaneaste.';

  @override
  String get ciSwitchVerified => 'Verificado';

  @override
  String get ciSwitchComparedAgain => 'Lo he comparado de nuevo';

  @override
  String get ciSwitchMarkVerified => 'Marcar como verificado';

  @override
  String get ciPillClassical => 'Clásico';

  @override
  String get ciPillPqPending => 'Poscuántico pendiente';

  @override
  String get ciPillPq => 'Poscuántico';

  @override
  String get ciNoticeVerified => 'Verificado';

  @override
  String ciNoticeVerifiedBody(String name) {
    return 'Este es el número que comparaste con $name.';
  }

  @override
  String get ciNoticeUpgraded => 'El número cambió, y este es el motivo';

  @override
  String ciNoticeUpgradedBody(String name) {
    return 'La identidad de $name obtuvo una clave poscuántica, así que el número ahora se deriva de ambas mitades. Es una actualización y ocurre una sola vez. No es señal de que nadie haya manipulado nada, pero el número que comprobaste antes ya no sirve, así que léelo en voz alta y compáralo de nuevo.';
  }

  @override
  String get ciNoticeChanged =>
      'El número cambió y esta app no puede explicar por qué';

  @override
  String ciNoticeChangedBody(String name) {
    return 'El número que verificaste con $name no es el que se muestra ahora, y esto no es la actualización poscuántica única. No te fíes de la verificación anterior. Compara el número de abajo en persona o en una llamada de confianza antes de continuar.';
  }

  @override
  String get disappearingMessages => 'Mensajes temporales';

  @override
  String get you => 'Tú';

  @override
  String sizeB(String b) {
    return '$b B';
  }

  @override
  String get chatMicPermission =>
      'Se necesita permiso de micrófono para grabar.';

  @override
  String get chatRecordingUnavailable =>
      'La grabación no está disponible en este dispositivo.';

  @override
  String get chatVoiceTooShort => 'Mensaje de voz demasiado corto.';

  @override
  String chatSendFailed(String error) {
    return 'Error al enviar: $error';
  }

  @override
  String get chatTooFarBack =>
      'Ese mensaje está demasiado atrás para saltar hasta él.';

  @override
  String get chatEditTitle => 'Editar mensaje';

  @override
  String get chatEditHint => 'Mensaje';

  @override
  String get chatEditExpired => 'Ese mensaje ya no se puede editar.';

  @override
  String get chatDeleteEveryoneTitle => '¿Eliminar para todos?';

  @override
  String get chatDeleteEveryoneBody =>
      'El mensaje se elimina aquí y se pide a la otra parte que también lo elimine. Quien ya lo haya leído puede haber guardado una copia; ninguna app puede deshacer eso.';

  @override
  String get chatNoForwardTarget =>
      'No hay otra conversación a la que reenviar.';

  @override
  String get chatForwardTo => 'Reenviar a';

  @override
  String get chatForwarded => 'Reenviado.';

  @override
  String chatForwardFailed(String error) {
    return 'Error al reenviar: $error';
  }

  @override
  String chatReactionFailed(String error) {
    return 'Error en la reacción: $error';
  }

  @override
  String get ttlOff => 'Desactivados';

  @override
  String ttlSeconds(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count segundos',
      one: '1 segundo',
    );
    return '$_temp0';
  }

  @override
  String ttlMinutes(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count minutos',
      one: '1 minuto',
    );
    return '$_temp0';
  }

  @override
  String ttlHours(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count horas',
      one: '1 hora',
    );
    return '$_temp0';
  }

  @override
  String ttlDays(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count días',
      one: '1 día',
    );
    return '$_temp0';
  }

  @override
  String ttlWeeks(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count semanas',
      one: '1 semana',
    );
    return '$_temp0';
  }

  @override
  String get chatConversationRemoved => 'Conversación eliminada';

  @override
  String chatGroupSubtitle(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count miembros · cifrado de extremo a extremo',
      one: '1 miembro · cifrado de extremo a extremo',
    );
    return '$_temp0';
  }

  @override
  String get chatSubVerified => 'cifrado de extremo a extremo · verificado';

  @override
  String get chatSubReverify =>
      'cifrado de extremo a extremo · volver a verificar';

  @override
  String get chatSubNumberChanged =>
      'cifrado de extremo a extremo · el número cambió';

  @override
  String get chatSubEncrypted => 'cifrado de extremo a extremo';

  @override
  String get chatLeftGroupNotice =>
      'Ya no estás en este grupo. El historial se queda en este dispositivo; no se pueden enviar ni recibir mensajes nuevos.';

  @override
  String get chatRecordingHint => 'Grabando… se envía cifrado, como todo';

  @override
  String get chatDiscard => 'Descartar';

  @override
  String get chatSendVoice => 'Enviar mensaje de voz';

  @override
  String get chatAttachFile => 'Adjuntar un archivo';

  @override
  String get chatInputHint => 'Mensaje cifrado…';

  @override
  String get chatReplyHint => 'Responder…';

  @override
  String get chatRecordVoice => 'Grabar un mensaje de voz';

  @override
  String get chatForwardedLabel => 'Reenviado';

  @override
  String get chatYouDeleted => 'Eliminaste este mensaje';

  @override
  String get chatTheyDeleted => 'Este mensaje fue eliminado';

  @override
  String get chatFailedTapRetry => 'Error al enviar: toca para reintentar';

  @override
  String chatRemoveReaction(String emoji) {
    return 'Quitar la reacción $emoji';
  }

  @override
  String chatReactWith(String emoji) {
    return 'Reaccionar con $emoji';
  }

  @override
  String chatReactionChip(String emoji, int count) {
    return '$emoji $count';
  }

  @override
  String get chatReply => 'Responder';

  @override
  String get chatCopyText => 'Copiar texto';

  @override
  String get chatForward => 'Reenviar';

  @override
  String get chatEdit => 'Editar';

  @override
  String get chatDeleteForEveryone => 'Eliminar para todos';

  @override
  String get chatRetrySend => 'Reintentar envío';

  @override
  String get chatRetryFailed => 'No se pudo reintentar este mensaje.';

  @override
  String get chatDeleteForMe => 'Eliminar para mí';

  @override
  String get chatSomeone => 'Alguien';

  @override
  String get chatThem => 'Tu contacto';

  @override
  String get chatReplyingToSelf => 'Respondiéndote a ti';

  @override
  String get chatReplyingToThem => 'Respondiendo a tu contacto';

  @override
  String chatReplyingTo(String name) {
    return 'Respondiendo a $name';
  }

  @override
  String get chatCancelReply => 'Cancelar respuesta';

  @override
  String get chatMessageUnavailable => 'Mensaje no disponible';

  @override
  String get chatImage => 'Imagen';

  @override
  String get chatSaveDialogTitle => 'Guardar copia descifrada';

  @override
  String get chatSavedDecrypted => 'Guardado (copia descifrada)';

  @override
  String chatSaveFailed(String error) {
    return 'Error al guardar: $error';
  }

  @override
  String get onbTagline =>
      'Mensajería de confianza cero.\nSin cuentas. Sin número de teléfono. Sin almacenamiento en servidores.';

  @override
  String get ok => 'Aceptar';

  @override
  String get stSettings => 'Ajustes';

  @override
  String get stProfile => 'Perfil';

  @override
  String get stDisplayName => 'Nombre para mostrar';

  @override
  String get stDisplayNameSaved =>
      'Guardado. Comparte un código de contacto nuevo para que los contactos nuevos lo vean.';

  @override
  String get stAppearance => 'Apariencia';

  @override
  String get stTheme => 'Tema';

  @override
  String get stThemeSystem => 'Sistema';

  @override
  String get stThemeLight => 'Claro';

  @override
  String get stThemeDark => 'Oscuro';

  @override
  String get stConnection => 'Conexión';

  @override
  String get stRelay => 'Relay';

  @override
  String get stRelayConnected =>
      'Conectado: enlace de conocimiento cero activo';

  @override
  String get stRelayConnecting => 'Conectando…';

  @override
  String get stRelayOffline => 'Sin conexión';

  @override
  String stRelayOfflineWithError(String error) {
    return 'Sin conexión ($error)';
  }

  @override
  String get stDevices => 'Dispositivos';

  @override
  String get stLinkedDevices => 'Dispositivos vinculados';

  @override
  String get stLinkedDevicesHelp =>
      'Consulta los dispositivos de tu cuenta, vincula uno nuevo o revoca uno que ya no uses.';

  @override
  String get stNotifications => 'Notificaciones';

  @override
  String get stPush => 'Notificaciones push';

  @override
  String get stPushHelp =>
      'Despierta este dispositivo cuando llegue un mensaje con Z cerrada. El aviso no contiene contenido: los mensajes se descargan y descifran solo en tu dispositivo, nunca dentro de la notificación.';

  @override
  String get stSecurity => 'Seguridad';

  @override
  String get stKeystoreUnavailable =>
      'Almacén de claves del sistema no disponible';

  @override
  String get stKeystoreUnavailableHelp =>
      'La clave de la bóveda se guarda en un archivo restringido en lugar del llavero del sistema. Instala o activa un llavero (p. ej. GNOME Keyring o KWallet en Linux) y vuelve a crear tu identidad para tener protección respaldada por hardware.';

  @override
  String get stWhereMessagesLive => 'Dónde viven tus mensajes';

  @override
  String get stWhereMessagesLiveHelp =>
      'Solo en la bóveda cifrada de este dispositivo (XChaCha20-Poly1305, clave en el almacén de claves del sistema). El relay conserva el texto cifrado solo en RAM hasta la entrega, nunca en disco.';

  @override
  String get stScreenLock => 'Bloqueo de pantalla';

  @override
  String stScreenLockOnHelp(String after) {
    return 'Z pide tu huella, rostro o PIN del dispositivo al abrirse y tras $after en segundo plano.';
  }

  @override
  String get stScreenLockOnImmediateHelp =>
      'Z pide tu huella, rostro o PIN del dispositivo al abrirse y en cuanto pasa a segundo plano.';

  @override
  String get stScreenLockOffHelp =>
      'Pide tu huella, rostro o PIN del dispositivo para abrir Z. Los mensajes siguen llegando mientras está bloqueada.';

  @override
  String get stLockAfter => 'Bloquear tras';

  @override
  String get lockImmediately => 'Inmediatamente';

  @override
  String get stPassphraseOn => 'Frase de contraseña de la app: activada';

  @override
  String get stPassphraseOff => 'Frase de contraseña de la app: desactivada';

  @override
  String get stPassphraseOnHelp =>
      'Este dispositivo pide tu frase de contraseña al iniciar. Toca para cambiarla o quitarla.';

  @override
  String get stPassphraseOffHelp =>
      'Añade una frase de contraseña que desbloquee la app en este dispositivo. Se combina con el almacén de claves del dispositivo; nunca se envía a ningún sitio.';

  @override
  String get stBiometricBound => 'Desbloqueo biométrico: ligado al hardware';

  @override
  String get stBiometric => 'Desbloqueo biométrico';

  @override
  String get stBiometricLead =>
      'Abre la bóveda con tu huella o rostro en lugar de escribir la frase de contraseña. ';

  @override
  String get stBiometricBoundBody =>
      'La clave que la abre está sellada por el hardware seguro de este dispositivo y solo puede usarse justo después del aviso del sistema; copiar los datos de la app no la revela. Registrar de nuevo una huella o un rostro la restablece.';

  @override
  String get stBiometricUnboundBody =>
      'Mientras esté activado, una clave derivada de tu frase de contraseña (nunca la frase en sí) reside en el almacén de claves de este dispositivo, así que en ESTE dispositivo, quien logre entrar en el almacén de claves ya no necesita tu frase de contraseña. Desactivarlo elimina esa clave.';

  @override
  String get stBackup => 'Copia de seguridad';

  @override
  String get stBackupHelp =>
      'Todo, mensajes, contactos, grupos y adjuntos, cifrado con un código de recuperación que solo tú tienes.';

  @override
  String get stDeveloper => 'Desarrollador';

  @override
  String get stDevMode => 'Modo desarrollador';

  @override
  String get stDevModeHelp =>
      'Muestra la dirección de relay personalizada, para un relay autoalojado o de pruebas. Desactivado por defecto: Z usa su relay integrado.';

  @override
  String get stRelayAddress => 'Dirección del relay';

  @override
  String get stRelayUrlTitle => 'URL del servidor relay';

  @override
  String get stConnect => 'Conectar';

  @override
  String get stDangerZone => 'Zona de peligro';

  @override
  String get stWipe => 'Borrar todo';

  @override
  String get stWipeHelp =>
      'Destruye la identidad, los contactos, los mensajes y las claves de este dispositivo.';

  @override
  String get stWipeTitle => '¿Borrar todo?';

  @override
  String get stWipeBody =>
      'Tu identidad, contactos, mensajes y adjuntos se destruirán en este dispositivo. Sin una copia .zid tu identidad es irrecuperable: ningún servidor tiene una copia.';

  @override
  String get stWipeAction => 'Borrar';

  @override
  String get stFooter =>
      'Z — mensajería de confianza cero\nSin cuentas · Sin analíticas · Sin almacenamiento en servidores';

  @override
  String get stScreenLockOn =>
      'Bloqueo de pantalla activado. Z preguntará antes de abrirse.';

  @override
  String get stScreenLockUnavailable =>
      'Configura primero una huella, un rostro o un PIN en los ajustes del sistema.';

  @override
  String get stPromptNotCompleted => 'No activado: el aviso no se completó.';

  @override
  String get stBackupPassphraseTitle => 'Frase de contraseña de la copia';

  @override
  String get stPassphraseMinLabel =>
      'Frase de contraseña (12 caracteres o más)';

  @override
  String get stRepeat => 'Repetir';

  @override
  String get stPassphraseTooShort => 'Usa al menos 12 caracteres.';

  @override
  String get stPassphraseMismatch => 'Las frases de contraseña no coinciden.';

  @override
  String get stEncryptAndSave => 'Cifrar y guardar';

  @override
  String get stBiometricOff =>
      'Desbloqueo biométrico desactivado: la clave guardada se ha eliminado.';

  @override
  String get stEnterPassphrase => 'Introduce tu frase de contraseña';

  @override
  String get stBiometricOn => 'Desbloqueo biométrico activado.';

  @override
  String get stIncorrectPassphrase => 'Frase de contraseña incorrecta.';

  @override
  String stCouldNotEnable(String error) {
    return 'No se pudo activar: $error';
  }

  @override
  String get stPassphraseSet =>
      'Frase de contraseña establecida. Se te pedirá en el próximo inicio.';

  @override
  String get stChangePassphrase => 'Cambiar la frase de contraseña';

  @override
  String get stRemovePassphrase => 'Quitar la frase de contraseña';

  @override
  String get stEnterCurrentPassphrase =>
      'Introduce la frase de contraseña actual';

  @override
  String get stPassphraseChanged => 'Frase de contraseña cambiada.';

  @override
  String get stPassphraseRemoved =>
      'Frase de contraseña eliminada. La app ahora se abre automáticamente.';

  @override
  String sysPqMismatch(String name) {
    return 'La clave poscuántica de $name no coincide con el código que escaneaste. Su identidad no se ha actualizado: compara los números de seguridad antes de confiar en este chat.';
  }

  @override
  String get sysSessionReset => 'La sesión segura se restableció.';

  @override
  String get sysTtlOffYou => 'Desactivaste los mensajes temporales.';

  @override
  String sysTtlSetYou(String duration) {
    return 'Configuraste los mensajes temporales a $duration.';
  }

  @override
  String sysDecryptFailed(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other:
          '$count mensajes no se pudieron descifrar (sesión restablecida). Pide que los reenvíen.',
      one:
          'Un mensaje no se pudo descifrar (sesión restablecida). Pide que lo reenvíen.',
    );
    return '$_temp0';
  }

  @override
  String sysTtlOffThem(String name) {
    return '$name desactivó los mensajes temporales.';
  }

  @override
  String sysTtlSetThem(String name, String duration) {
    return '$name configuró los mensajes temporales a $duration.';
  }

  @override
  String get sysAttachmentDiscarded =>
      'Un adjunto no superó las comprobaciones de integridad y se descartó.';

  @override
  String get sysLeftYou => 'Saliste del grupo.';

  @override
  String sysCreatedYou(String name) {
    return 'Creaste «$name».';
  }

  @override
  String sysAddedYou(String names) {
    return 'Añadiste a $names.';
  }

  @override
  String sysRemovedYou(String name) {
    return 'Quitaste a $name.';
  }

  @override
  String sysRemovedFrom(String name) {
    return 'Te quitaron de «$name».';
  }

  @override
  String sysAddedToBy(String by, String name) {
    return '$by te añadió a «$name».';
  }

  @override
  String get sysMembershipUpdated => 'Miembros del grupo actualizados.';

  @override
  String sysMemberLeft(String name) {
    return '$name salió del grupo.';
  }

  @override
  String get sysAMember => 'un miembro';

  @override
  String get sysSomeone => 'Alguien';

  @override
  String get sysUnknownMemberLeft => 'Un miembro salió del grupo.';

  @override
  String ktBannerHeld(String name) {
    return 'La lista de dispositivos más reciente de $name no está en el registro de transparencia. Los dispositivos que solo esa lista añadió no reciben tus mensajes hasta que aparezca.';
  }

  @override
  String ktBannerConflict(String name) {
    return 'El registro de transparencia y los dispositivos de $name no coinciden sobre su lista de dispositivos. Tus mensajes para esta persona quedan retenidos hasta que coincidan, o hasta que elijas enviar de todos modos.';
  }

  @override
  String get ktSendAnyway => 'Enviar de todos modos';

  @override
  String get ktComposerHeld =>
      'Los mensajes a este contacto están retenidos; mira el aviso de arriba.';

  @override
  String homeKtOwnAlert(int v) {
    return 'Se ha publicado en el registro de transparencia una lista de dispositivos de tu cuenta que tú no emitiste (versión $v). Revisa ahora tus dispositivos vinculados.';
  }

  @override
  String homeKtFault(String reason) {
    return 'El registro de transparencia ha mostrado dos historiales distintos: $reason. No se está confirmando nada nuevo. Ajustes › Registro de transparencia tiene los detalles.';
  }

  @override
  String homeKtUnreachable(String when) {
    return 'El registro de transparencia no responde desde $when. Mientras tanto, las listas de dispositivos las comprueban solo los dispositivos de tus contactos.';
  }

  @override
  String get ciKtTitle => 'Registro de transparencia';

  @override
  String ciKtConfirmed(int v) {
    return 'Confirmado: su lista de dispositivos (versión $v) es la que está en el registro.';
  }

  @override
  String get ciKtUnlogged =>
      'No está en el registro. Esta cuenta nunca ha publicado una lista de dispositivos: una app antigua, o una que no se ha conectado desde que se actualizó.';

  @override
  String ciKtUnconfirmed(int held, int log) {
    return 'Su lista de dispositivos más reciente (versión $held) aún no está en el registro; el registro tiene la versión $log.';
  }

  @override
  String ciKtConflict(int v) {
    return 'El registro tiene en la versión $v una lista de dispositivos distinta de la que enviaron sus dispositivos. Los mensajes para esta persona están retenidos.';
  }

  @override
  String get ciKtOff =>
      'No hay ningún registro de transparencia configurado en este dispositivo.';

  @override
  String get ciKtUnchecked => 'Aún no se ha comprobado.';

  @override
  String get stTransparency => 'Registro de transparencia';

  @override
  String get stKtStatus => 'Estado';

  @override
  String get stKtHealthOff => 'No configurado';

  @override
  String get stKtHealthUnknown => 'Aún no comprobado';

  @override
  String stKtHealthOk(String when, int n) {
    return 'Verificado $when — $n entradas';
  }

  @override
  String stKtHealthUnreachable(String when) {
    return 'Sin respuesta desde $when';
  }

  @override
  String stKtHealthFault(String reason) {
    return 'Fallo: $reason';
  }

  @override
  String get stKtCheckNow => 'Comprobar ahora';

  @override
  String get stKtChecked => 'Comprobado.';

  @override
  String get stKtLogAddress => 'Dirección del registro';

  @override
  String get stKtLogUrlTitle => 'URL del registro de transparencia';

  @override
  String get stKtLogKey => 'Clave pública del registro';

  @override
  String get stKtLogKeyTitle => 'Clave pública del registro (base64)';

  @override
  String get stKtWitness => 'Dirección del testigo';

  @override
  String get stKtWitnessTitle => 'URL del registro del testigo';

  @override
  String get stKtWitnessKey => 'Clave pública del testigo';

  @override
  String get stKtWitnessKeyTitle => 'Clave pública del testigo (base64)';

  @override
  String get stKtNone => 'ninguna';

  @override
  String get stKtReset => 'Olvidar el historial del registro';

  @override
  String get stKtResetHelp =>
      'Empezar de nuevo desde la cabecera actual del registro. Solo tras cambiar de registro a propósito, o una vez notificado un fallo.';

  @override
  String get stKtResetConfirm => '¿Olvidar el historial del registro?';

  @override
  String get stKtSave => 'Guardar';

  @override
  String get stCryptoBench => 'Prueba de rendimiento criptográfico';

  @override
  String get stCryptoBenchHelp =>
      'Mide cada primitiva que Z usa, en este dispositivo';

  @override
  String cbRunning(int n) {
    return 'Midiendo… $n listas';
  }

  @override
  String cbDone(int n) {
    return 'Hecho — $n mediciones';
  }

  @override
  String get cbNote =>
      'Cada línea es Dart puro: la app no usa ninguna implementación de la plataforma. La línea de Argon2id es lo que cuesta aquí desbloquear con contraseña. Medianas; el reloj y la temperatura del teléfono las mueven.';

  @override
  String get cbCopy => 'Copiar como tabla';

  @override
  String get cbCopied => 'Copiado';

  @override
  String get cbAgain => 'Repetir';
}
