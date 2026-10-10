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
  String get unlockBiometricStale =>
      'El desbloqueo biométrico está obsoleto: introduce tu frase de contraseña y vuelve a activarlo en Ajustes.';

  @override
  String get unlockBiometricInvalidated =>
      'Tus huellas o tu rostro cambiaron, así que el desbloqueo biométrico se restableció. Introduce tu frase de contraseña y vuelve a activarlo en Ajustes.';

  @override
  String get vaultTooNew =>
      'Los datos de este dispositivo los guardó una versión más reciente de Z. Actualiza Z para abrirlos; no se ha cambiado nada.';

  @override
  String startupFailed(String detail) {
    return 'Z no pudo iniciarse:\n$detail';
  }

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
  String get voicePlaybackOff =>
      'La reproducción de voz está desactivada en este ordenador';

  @override
  String get voiceNoLibmpvLinux =>
      'Los mensajes de voz no se pueden reproducir en este ordenador: libmpv, la biblioteca con la que Z los reproduce, no está instalada. Instálala con tu gestor de paquetes (libmpv2 en Debian y Ubuntu, o libmpv1 en versiones anteriores; mpv-libs en Fedora; mpv en Arch) y reinicia Z. Todo lo demás funciona, y un mensaje de voz se puede seguir guardando desde su menú.';

  @override
  String get voiceNoLibmpvWindows =>
      'Los mensajes de voz no se pueden reproducir en este ordenador: falta libmpv-2.dll, que viene con Z, o no se pudo cargar. Vuelve a descomprimir la descarga de Z con todos sus archivos juntos y reinicia Z. Todo lo demás funciona, y un mensaje de voz se puede seguir guardando desde su menú.';

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
  String contactUpgraded(String name) {
    return '$name ya estaba en tus contactos: su compromiso poscuántico se ha tomado de este código.';
  }

  @override
  String contactUpgradedUnsigned(String name) {
    return '$name ya estaba en tus contactos. El compromiso poscuántico de este código no está firmado, así que solo se usará si coincide con la clave que envíe su app.';
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
  String get addShareCode => 'Compartir';

  @override
  String get addOpenImage => 'Abrir una imagen QR';

  @override
  String get addNoCodeInImage => 'No se encontró ningún código en esa imagen.';

  @override
  String get addTheirCode => 'Su código de contacto';

  @override
  String get addNameOverride => 'Nombre (opcional: sustituye al suyo)';

  @override
  String get addVerifyAndAdd => 'Verificar y añadir';

  @override
  String get addSignatureNote =>
      'Las firmas del código se comprueban antes de añadir el contacto, y se rechaza un código cuyas claves se hayan alterado. Su parte poscuántica también se comprueba: con su propia firma cuando la lleva, con lo que ya tengas de esa persona y con su clave cuando llegue. El nombre de un código es solo una sugerencia.';

  @override
  String addRefusedCommitStripped(String name) {
    return 'A este código le falta el compromiso poscuántico firmado que llevan los códigos de $name. Puede ser un código antiguo suyo, o alguien lo quitó. No se ha cambiado nada: pide a $name su código actual.';
  }

  @override
  String addRefusedUnsignedCommit(String name) {
    return 'El compromiso poscuántico de este código no coincide con la clave que envió la app de $name, y nada en el código lo firma, así que puede haberse alterado. No se ha cambiado nada. Comparad el número de seguridad con $name en su lugar.';
  }

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
  String get onbBackupTooNew =>
      'Esta copia de seguridad la hizo una versión más reciente de Z. Actualiza Z primero y luego restáurala; la copia no se ha modificado.';

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
  String get grpRemoveTitle => '¿Quitar al miembro?';

  @override
  String grpRemoveBody(String name) {
    return '$name será quitado del grupo para todos y no podrá volver a añadirse sin una nueva invitación. No se puede deshacer.';
  }

  @override
  String get grpRemoveConfirm => 'Quitar';

  @override
  String get grpLeaveGroup => 'Salir del grupo';

  @override
  String get grpFootnote =>
      'Los grupos no existen en ningún servidor: el relay nunca conoce el nombre del grupo ni la lista de miembros. Cada mensaje se envía como copias separadas cifradas de extremo a extremo por vuestros canales 1:1 verificados.';

  @override
  String get grpMsgPqBody =>
      'Los mensajes nuevos de este grupo, en ambos sentidos, están protegidos por el intercambio de claves poscuántico (ML-KEM-768) además de X25519, en todos los dispositivos a los que llegan.';

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
  String get linkPeerTooOld =>
      'El otro dispositivo tiene una versión anterior de Z. Actualízalo y vuelve a emparejar: esta versión no recurrirá al emparejamiento anterior.';

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
      'Tus dispositivos vinculados se mantienen sincronizados: los mensajes que envías y recibes aparecen en todos, y tus contactos también se copian. La vinculación establece la conexión verificada y de confianza por la que viajan.';

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
      'Su lista de dispositivos también está firmada de forma poscuántica, así que no se puede añadir ni quitar un dispositivo del conjunto al que envías sin que esa firma falle. Todavía no cubre la clave con la que cada uno de sus dispositivos vinculados recibe los mensajes: esa clave solo está firmada de forma clásica, así que alguien con la clave de su cuenta —o, algún día, un ordenador cuántico— podría cambiarla sin que aquí cambie nada.';

  @override
  String get ciDevListClassical =>
      'Su lista de dispositivos está firmada solo de forma clásica. Hoy es correcto; la firma poscuántica viaja por separado y puede que aún no haya llegado.';

  @override
  String get ciDevListHybridKeys =>
      'Su lista de dispositivos también está firmada de forma poscuántica, incluida la clave con la que cada uno de sus dispositivos recibe los mensajes, así que el conjunto al que envías no puede falsificarse ni cambiarse en silencio.';

  @override
  String get ciReaderBehind =>
      'Puede que su app no lea tu lista de dispositivos';

  @override
  String ciReaderBehindBody(String name) {
    return 'Tu lista de dispositivos ya se firma en el formato nuevo, que las apps anteriores a la 3.9.9 no pueden leer, y la app de $name no ha dicho que pueda leerlo. Si es tan antigua, no llega a tus otros dispositivos y puede mostrarle avisos sobre tu cuenta hasta que la actualice. No pasa nada malo con ninguna de las dos cuentas.';
  }

  @override
  String get ciMsgPqTitle => 'Mensajes: poscuánticos';

  @override
  String get ciMsgPqBody =>
      'Los mensajes nuevos de este chat, en ambos sentidos, están protegidos por el intercambio de claves poscuántico (ML-KEM-768) además de X25519, en todos los dispositivos a los que llegan.';

  @override
  String get ciMsgNotYetTitle => 'Mensajes: aún no poscuánticos';

  @override
  String ciMsgNotYetBody(String channels) {
    return 'El intercambio de claves poscuántico no se ha completado con $channels, así que esos mensajes aún no están protegidos por él en los dos sentidos. Para completarse necesita mensajes en ambos sentidos; hasta entonces, alguien que grabe ese tráfico hoy podría leer parte de él, o todo, con un futuro ordenador cuántico.';
  }

  @override
  String ciMsgChanContact(String name) {
    return 'el dispositivo de $name';
  }

  @override
  String ciMsgChanTheirOther(int count, String name) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count de los otros dispositivos de $name',
      one: '1 de los otros dispositivos de $name',
    );
    return '$_temp0';
  }

  @override
  String ciMsgChanMine(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count de tus otros dispositivos',
      one: '1 de tus otros dispositivos',
    );
    return '$_temp0';
  }

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
  String get ciResetTitle => '¿Restablecer la sesión segura?';

  @override
  String get ciResetBody =>
      'Esto descarta la sesión de cifrado actual con este contacto. Lo que ya esté en camino y aún no haya llegado podría perderse. Hazlo solo si los mensajes han dejado de descifrarse.';

  @override
  String get ciResetConfirm => 'Restablecer';

  @override
  String get ciDeleteContact => 'Eliminar contacto y todos los mensajes';

  @override
  String get ciDeleteTitle => '¿Eliminar todo?';

  @override
  String get ciDeleteBody =>
      'Esto borra de ESTE dispositivo el contacto y tu chat con esa persona, con todos sus adjuntos. Lo que el chat de un grupo guarde de esa persona se queda en ese chat. No hay copia en ningún servidor desde la que restaurar; esa es la idea.';

  @override
  String ciDeleteBodyInGroups(int count, String groups) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other:
          'Esto borra de ESTE dispositivo el contacto y tu chat con esa persona, con todos sus adjuntos, pero no lo que los grupos $groups guardan de ella: borrar un contacto no saca a nadie de un grupo.',
      one:
          'Esto borra de ESTE dispositivo el contacto y tu chat con esa persona, con todos sus adjuntos, pero no lo que el grupo $groups guarda de ella: borrar un contacto no saca a nadie de un grupo.',
    );
    return '$_temp0 Como un grupo sigue nombrando a sus miembros, este dispositivo conserva su id de enrutamiento, su clave pública y su nombre en el registro de cada grupo; y mientras siga en un grupo, un cambio que haga en él otra persona —o tú desde otro dispositivo— la vuelve a añadir como contacto, como a cualquier miembro. Quitarla del grupo, o salir de él, la borra de su registro. Lo que el chat de un grupo guarde de esa persona se queda en ese chat. No hay copia en ningún servidor desde la que restaurar; esa es la idea.';
  }

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
  String get ciBlurbWaiting =>
      'Su clave poscuántica ya ha llegado, pero ellos aún no tienen la tuya, así que el número de abajo sigue siendo el de Ed25519: el mismo que muestra su dispositivo. Pasará a ser el número poscuántico en ambos dispositivos a la vez, en cuanto cada uno tenga la clave del otro.';

  @override
  String get ciBlurbCandidate =>
      'El número de abajo cubre ambas mitades de ambas identidades, pero esta aplicación no ha podido comprobar su clave poscuántica contra nada: los añadiste desde un código anterior a ella, o te la enviaron después de añadirlos. Comparar este número ES la comprobación: si coincide en su dispositivo, la clave es suya, y confirmarlo abajo lo deja registrado.';

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
  String get ciBlurbRefused =>
      'Llegó una clave poscuántica para este contacto que NO coincide con el código que escaneaste, así que fue rechazada. El número de abajo es el de Ed25519: el único que aquí significa algo. Esta identidad no se actualizará mientras el rechazo siga sin resolverse; lee el aviso de arriba.';

  @override
  String get ciPillPqRefused => 'Clave rechazada';

  @override
  String get ciPillPqWaiting => 'Esperándoles';

  @override
  String get ciPillPqUnconfirmed => 'Poscuántico, sin confirmar';

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
  String get chatAttachCamera => 'Hacer una foto';

  @override
  String get chatAttachGallery => 'Foto o vídeo';

  @override
  String get chatAttachFileOption => 'Archivo';

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
  String get stPushOnHelp =>
      'Cuando te espera un mensaje con Z cerrada, el relay pide a Firebase Cloud Messaging de Google que despierte este dispositivo, usando un token que este dispositivo le dio. El aviso no lleva ningún mensaje ni remitente: Google solo sabe que este dispositivo fue despertado, y cuándo. El relay guarda el token hasta 30 días después de la última conexión de este dispositivo, o hasta que desactives las notificaciones push.';

  @override
  String get stPushOffHelp =>
      'Desactivadas. El relay no guarda ningún token push de este dispositivo y nada lo despierta: Z descarga tus mensajes cuando la abres.';

  @override
  String get stPushOffPendingHelp =>
      'Desactivadas. Se le pedirá al relay que olvide el token push de este dispositivo la próxima vez que este esté en línea; hasta entonces aún puede despertarlo.';

  @override
  String get stPushNotAllowedHelp =>
      'Las notificaciones no están permitidas para Z, así que este dispositivo no está registrado para push y nada lo despierta: Z descarga tus mensajes cuando la abres. Permite las notificaciones de Z en los ajustes de Android para usar push.';

  @override
  String get stPushNotAllowedPendingHelp =>
      'Las notificaciones no están permitidas para Z, así que push está desactivado. Se le pedirá al relay que olvide el token push de este dispositivo la próxima vez que este esté en línea; hasta entonces aún puede despertarlo.';

  @override
  String get stPrivacy => 'Privacidad';

  @override
  String get stReceipts => 'Confirmaciones de entrega y de lectura';

  @override
  String get stReceiptsOnHelp =>
      'Quienes te escriben ven un segundo tic cuando su mensaje llega a este dispositivo, y los tics cambian de color cuando lo has leído. Cada confirmación espera entre 5 segundos y un minuto, al azar —o, pasados esos 5 segundos, sale con tu próximo mensaje a esa persona—, así que nunca se envía en el momento en que llega el mensaje. Solo en este dispositivo.';

  @override
  String get stReceiptsOffHelp =>
      'Desactivadas. Este dispositivo no avisa a nadie de cuándo llega su mensaje ni de cuándo lo lees, así que verán un solo tic, nunca dos, aunque el mensaje haya llegado. Tus otros dispositivos responden por sí mismos.';

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
  String get stWipeFailedTitle => 'No se pudo eliminar todo';

  @override
  String get stWipeFailedBody =>
      'Parte de tus datos sigue en este dispositivo, así que no se informó nada como borrado. Cierra la aplicación, asegúrate de que no esté en ejecución e inténtalo de nuevo, o desinstala la aplicación, lo que elimina sus archivos.';

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
  String stVersion(String version) {
    return 'Versión $version';
  }

  @override
  String get stUpdateTitle => 'Actualización disponible';

  @override
  String stUpdateBody(String version) {
    return 'Z $version ya está disponible. Z no tiene actualización dentro de la app, por diseño; consíguela en:';
  }

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
  String ktBannerGroupHeld(String names, int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other:
          'Los mensajes para $names están retenidos: el registro de transparencia no coincide con sus listas de dispositivos, así que este mensaje no les ha llegado.',
      one:
          'Los mensajes para $names están retenidos: el registro de transparencia no coincide con su lista de dispositivos, así que este mensaje no le ha llegado.',
    );
    return '$_temp0';
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
  String homeOwnOlderList(int sent, int held) {
    return 'Tu dispositivo principal publicó una lista de dispositivos más antigua (v$sent) que la que este dispositivo ya tiene (v$held). La lista más reciente fue firmada por otro dispositivo que tiene la clave de tu cuenta. Si no fuiste tú, restablece tu identidad ahora.';
  }

  @override
  String get homeOwnUnissued =>
      'A un contacto se le entregó una lista de dispositivos de tu cuenta que este dispositivo nunca emitió. Puede que un dispositivo con la clave de tu cuenta haya inscrito otro dispositivo. Si no fuiste tú, restablece tu identidad ahora.';

  @override
  String homeRemovedDevice(int v) {
    return 'Este dispositivo fue eliminado de tu cuenta (lista de dispositivos v$v). Si no lo hiciste tú, puede que la clave de tu cuenta esté comprometida: restablece tu identidad.';
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
  String get stKtWitness => 'Testigo';

  @override
  String get stKtWitnessTitle => 'URL del registro del testigo';

  @override
  String get stKtWitnessEdit => 'Testigo';

  @override
  String get stKtWitnessHelp =>
      'Un testigo es una dirección y la clave que fijas para ella. Ambas, o ninguna: una dirección sola permitiría que quien responda firme junto al registro con una clave que nunca elegiste.';

  @override
  String get stKtWitnessNeedsKey =>
      'Esa dirección necesita una clave. Sin ella, quien responda coincide con el registro usando una clave que nunca fijaste, y la comprobación no significa nada.';

  @override
  String get stKtWitnessNeedsUrl =>
      'Esa clave necesita una dirección. Por sí sola nunca se usa.';

  @override
  String get stKtWitnessBadKey =>
      'Una clave de testigo son 32 bytes, escritos en base64.';

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
  String get stDevlistSigning => 'Firma de la lista de dispositivos';

  @override
  String get stDevlistDual =>
      'Con doble firma, para que cualquier versión de la app pueda leerla. Su firma poscuántica cubre qué dispositivos están en ella, no sus claves.';

  @override
  String get stDevlistMoved =>
      'Firmada solo en v2. Su firma poscuántica y su huella cubren las claves de cada dispositivo.';

  @override
  String stDevlistContactsBehind(int count) {
    return 'Dispositivos de contactos aún no preparados: $count';
  }

  @override
  String stDevlistOwnBehind(int count) {
    return 'Tus otros dispositivos aún no preparados: $count';
  }

  @override
  String get stDevlistWaiting =>
      'Pasará a solo v2 por sí sola cuando ambos estén a 0.';

  @override
  String get stDevlistMoving => 'Pasando ahora a solo v2.';

  @override
  String get stDevlistNeedsBoth =>
      'Pasará cuando esta cuenta tenga un dispositivo vinculado y un contacto, y todos estén preparados.';

  @override
  String get stDevlistSwitchedOff =>
      'El paso está desactivado en esta versión.';

  @override
  String get stDevlistRootDecides =>
      'Tu dispositivo principal decide cuándo pasar.';

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

  @override
  String get addConnect => 'CONECTAR';

  @override
  String get connectIntro =>
      'Para alguien con quien no puedes quedar en persona. Envíale una invitación de un solo uso por cualquier canal — incluso uno en el que no confíes — y después comparad ocho dígitos para demostrar que nadie estaba en medio.';

  @override
  String get connectCreate => 'Crear una invitación';

  @override
  String get connectOpenTitle => 'Abrir una invitación';

  @override
  String get connectOpenField => 'Enlace o código de invitación';

  @override
  String get connectOpen => 'Abrir';

  @override
  String get connectShareLink => 'Copiar enlace';

  @override
  String get connectShareCode => 'Copiar código';

  @override
  String get connectCopied => 'Copiado';

  @override
  String get connectLinkLabel => 'Enlace';

  @override
  String get connectCodeLabel => 'Código';

  @override
  String get connectSameSecret =>
      'El enlace y el código son la misma invitación. Envía el que mejor le vaya al canal.';

  @override
  String get connectOneTime => 'Funciona una sola vez y caduca a las 24 horas.';

  @override
  String get connectPending => 'Esperando a que la abran';

  @override
  String get connectPendingOpened => 'Esperando a la otra persona';

  @override
  String get connectExpired => 'Caducada';

  @override
  String get connectAborted => 'Rechazada';

  @override
  String get connectDiscard => 'Descartar';

  @override
  String get connectCheck => 'Comprobar ahora';

  @override
  String connectLastFailure(String reason) {
    return 'No se pudo contactar con el relay; se seguirá intentando. ($reason)';
  }

  @override
  String get connectNoInvites => 'No hay invitaciones pendientes.';

  @override
  String get connectConfirmTitle => 'Comparad estos dígitos';

  @override
  String connectWhoAccepted(String name) {
    return '$name aceptó tu invitación. Cualquiera que tuviera el enlace pudo tomarla, así que si no es la persona con quien querías conectar, detente abajo en vez de añadirla.';
  }

  @override
  String get connectGroupNotice =>
      'Esta invitación también te añade a un grupo. Verás cuál cuando estéis conectados, y podrás salir de él cuando quieras.';

  @override
  String connectGroupLinkGoAhead(String group) {
    return 'Este enlace es para «$group»: si sigues adelante, entrará en el grupo en cuanto también siga adelante desde su lado.';
  }

  @override
  String connectGroupLinkTooOld(String group) {
    return 'Su aplicación es demasiado antigua para unirse a un grupo desde un enlace. Si sigues adelante, solo será un contacto: añádelo a «$group» a mano.';
  }

  @override
  String connectGroupLinkNotAdmin(String group) {
    return 'Ya no puedes añadir miembros a «$group», así que si sigues adelante solo será un contacto.';
  }

  @override
  String connectGroupLinkLabel(String group) {
    return 'Enlace al grupo «$group»';
  }

  @override
  String get connectJoinGroup => 'Unirme también al grupo';

  @override
  String connectJoinGroupOff(String name) {
    return 'Solo serás contacto de $name, y $name sabrá que decidiste no unirte.';
  }

  @override
  String connectGroupLinkExpired(String group) {
    return 'Las 24 horas de este enlace ya pasaron: si sigues adelante, solo será un contacto y no se añadirá a «$group».';
  }

  @override
  String connectAlreadyContact(String name) {
    return '$name ya era tu contacto; no ha cambiado nada.';
  }

  @override
  String connectAlreadyContactJoining(String name) {
    return '$name ya era tu contacto; no ha cambiado nada. Entrarás en el grupo cuando el dispositivo de $name te añada.';
  }

  @override
  String get connectLinkWaitsTitle => 'Esperando a que entren en tus grupos';

  @override
  String connectLinkWait(String name, String group) {
    return '$name, a «$group»';
  }

  @override
  String get connectLinkWaitStop => 'Dejar de esperar';

  @override
  String connectLinkWaitTooLate(String name, String group) {
    return 'Ya no se puede detener: $name ya había dicho que sí y se está añadiendo a «$group».';
  }

  @override
  String connectConfirmBody(Object name) {
    return 'Léele estos ocho dígitos a $name por teléfono o en persona. Tiene que ver exactamente los mismos. Si es así, nadie está en medio: ni el relé, ni la red, ni quien pudiera ver el mensaje que llevaba la invitación.';
  }

  @override
  String get connectMatch => 'Coinciden';

  @override
  String get connectNotYet => 'Todavía no los hemos comparado';

  @override
  String get connectMismatch => 'No coinciden';

  @override
  String connectAdded(Object name) {
    return '$name añadido y verificado';
  }

  @override
  String connectAddedUnverified(Object name) {
    return '$name añadido, pero sin verificar';
  }

  @override
  String get connectUnverifiedNote =>
      'Nadie comparó los dígitos, así que este contacto está sin verificar. Compara los números de seguridad desde su chat en cuanto puedas.';

  @override
  String get connectStopped => 'Detenido. No se añadió nada.';

  @override
  String get connectMismatchWarning =>
      'Si los dígitos no coinciden, alguien está retransmitiendo entre vosotros. No vuelvas a usar la misma invitación: crea otra y mándala por otra vía.';

  @override
  String get connectPendingTitle => 'Invitaciones en curso';

  @override
  String alertDlConflict(String name) {
    return 'Los dispositivos de $name no coinciden sobre su lista de dispositivos. Puede que uno de ellos no sea suyo: confírmalo con esa persona antes de continuar.';
  }

  @override
  String alertDlRollback(String name) {
    return 'La lista de dispositivos de $name retrocedió una versión. Puede que uno de sus dispositivos esté reproduciendo una lista antigua: confírmalo con esa persona.';
  }

  @override
  String alertDlUnconfirmed(String name) {
    return 'Los dispositivos de $name no confirman la lista de dispositivos que recibió este dispositivo. Puede que uno de los suyos no sea suyo: confírmalo con esa persona antes de continuar.';
  }

  @override
  String alertDlMissingUpdate(String name) {
    return 'La lista de dispositivos de $name cambió, pero la actualización nunca llegó. No se pudo verificar su nuevo dispositivo.';
  }

  @override
  String alertDlPqMissing(String name) {
    return 'La aplicación de $name dice que envió la firma poscuántica de su lista de dispositivos, y no ha llegado. Su lista de dispositivos sigue verificándose de forma clásica, lo cual funciona hoy pero es lo que un adversario cuántico futuro podría falsificar. Puede que algo en la red la esté eliminando.';
  }

  @override
  String alertDlShared(String name, String other) {
    return 'La lista de dispositivos de $name incluye un dispositivo que también incluye la lista de $other, así que no se ha usado. Un dispositivo pertenece a una sola cuenta y Z no puede saber cuál de las dos tiene razón: confírmalo con ambas personas.';
  }

  @override
  String alertDlSharedAnother(String name) {
    return 'La lista de dispositivos de $name incluye un dispositivo que también incluía la lista de otra cuenta, así que no se ha usado. Un dispositivo pertenece a una sola cuenta: confírmalo con esa persona.';
  }

  @override
  String alertDlSharedMine(String name) {
    return 'La lista de dispositivos de $name incluye uno de tus propios dispositivos, así que no se ha usado. Un dispositivo pertenece a una sola cuenta: confírmalo con esa persona.';
  }

  @override
  String alertDlClaimed(String name, String other) {
    return 'La lista de dispositivos de $name incluye un dispositivo que ha demostrado pertenecer a la cuenta de $other, así que la lista de $name no se usa. Un dispositivo pertenece a una sola cuenta: pregúntaselo a $name.';
  }

  @override
  String alertDlClaimedAnother(String name) {
    return 'La lista de dispositivos de $name incluye un dispositivo que ha demostrado pertenecer a otra cuenta, así que la lista de $name no se usa. Un dispositivo pertenece a una sola cuenta: pregúntaselo a $name.';
  }

  @override
  String get relayInsecureTitle => 'Este relay no usa TLS';

  @override
  String relayInsecureBody(String url) {
    return '$url es una dirección ws:// sin cifrar, así que cualquiera en la red entre tú y ese servidor puede ver de qué buzón recibes y con qué frecuencia: el patrón de con quién hablas, aunque nunca lo que dices. El contenido de los mensajes sigue cifrado de extremo a extremo sea cual sea el transporte. Usa wss:// para cualquier relay que no esté en tu propia red.';
  }

  @override
  String get relayInsecureUseAnyway => 'Conectar de todos modos';

  @override
  String connectExpiresHours(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: 'quedan $count horas',
      one: 'queda 1 hora',
    );
    return '$_temp0';
  }

  @override
  String connectExpiresMinutes(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: 'quedan $count minutos',
      one: 'queda 1 minuto',
    );
    return '$_temp0';
  }

  @override
  String get connectExpiresSoon => 'Queda menos de un minuto';

  @override
  String get connectQrLabel => 'Como código QR';

  @override
  String get connectShareSheet => 'Compartir';

  @override
  String get connectSharedToClipboard =>
      'Aquí no hay menú de compartir: el enlace se copió al portapapeles.';

  @override
  String get connectHeldStatus =>
      'Abierta desde un enlace: aún no se ha enviado nada';

  @override
  String get connectHeldBody =>
      'Al conectar, tu código de contacto se envía a quien creó esta invitación, y después comparáis ocho dígitos. Si no esperabas una invitación, descártala.';

  @override
  String get connectHeldGo => 'Conectar';

  @override
  String get connectOldInvite =>
      'Esta invitación la creó una versión anterior de Z. Hasta que comparéis los dígitos, incluso el relé podría estar en medio.';

  @override
  String get requestsTitle => 'Solicitudes';

  @override
  String requestsBanner(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count personas quieren conectar',
      one: '1 persona quiere conectar',
    );
    return '$_temp0';
  }

  @override
  String get requestsWantsToConnect => 'Quiere conectar';

  @override
  String get requestsNote =>
      'Aceptar la añade a tus chats. No confirma quién es: para eso, compara los números de seguridad.';

  @override
  String get requestsEmpty => 'No hay solicitudes ahora mismo';

  @override
  String get requestAccept => 'Aceptar';

  @override
  String get requestDecline => 'Rechazar';

  @override
  String get requestBlock => 'Bloquear';

  @override
  String get chatRequested => 'Solicitado';

  @override
  String get videoNoPlayback =>
      'Este vídeo no se puede reproducir aquí; guárdalo y ábrelo en otra aplicación.';

  @override
  String get chatPlayVideo => 'Reproducir vídeo';

  @override
  String get chatPauseVideo => 'Pausar vídeo';

  @override
  String get chatVideo => 'Vídeo';

  @override
  String sysRenamedYou(String name) {
    return 'Cambiaste el nombre del grupo a \"$name\".';
  }

  @override
  String sysRenamedBy(String by, String name) {
    return '$by cambió el nombre del grupo a \"$name\".';
  }

  @override
  String get grpRename => 'Cambiar el nombre del grupo';

  @override
  String sysPromotedYou(String name) {
    return 'Hiciste administrador a $name.';
  }

  @override
  String sysDemotedYou(String name) {
    return 'Quitaste a $name como administrador.';
  }

  @override
  String sysTransferredYou(String name) {
    return 'Hiciste propietario del grupo a $name.';
  }

  @override
  String sysPromotedBy(String by, String name) {
    return '$by hizo administrador a $name.';
  }

  @override
  String sysPromotedMeBy(String by) {
    return '$by te hizo administrador.';
  }

  @override
  String sysDemotedBy(String by, String name) {
    return '$by quitó a $name como administrador.';
  }

  @override
  String sysDemotedMeBy(String by) {
    return '$by te quitó como administrador.';
  }

  @override
  String sysOwnerBy(String by, String name) {
    return '$by hizo propietario del grupo a $name.';
  }

  @override
  String sysOwnerMeBy(String by) {
    return '$by te hizo propietario del grupo.';
  }

  @override
  String sysSteppedDown(String name) {
    return '$name ya no es administrador.';
  }

  @override
  String sysChangeOverriddenBy(String by) {
    return 'El cambio de $by en el grupo sustituyó al tuyo, que no se mantuvo. Vuelve a hacerlo si aún lo quieres.';
  }

  @override
  String get sysChangeOverriddenMine =>
      'Un cambio hecho en tu otro dispositivo en ese mismo momento sustituyó a este, que no se mantuvo. Vuelve a hacerlo si aún lo quieres.';

  @override
  String sysAddedFromLinkBy(String by, String name) {
    return '$by te añadió a «$name» desde el enlace que abriste.';
  }

  @override
  String sysLinkJoined(String name) {
    return '$name se unió con tu enlace de invitación.';
  }

  @override
  String sysLinkTooOld(String name) {
    return '$name es tu contacto, pero no se añadió a este grupo: su aplicación es demasiado antigua para unirse desde un enlace. Añádelo a mano.';
  }

  @override
  String sysLinkExpired(String name) {
    return '$name es tu contacto, pero no se añadió a este grupo: su confirmación para unirse no te llegó dentro de las 24 horas del enlace. Añádelo a mano si todavía quieres que esté aquí.';
  }

  @override
  String sysLinkRefused(String name) {
    return '$name es tu contacto, pero no se añadió a este grupo: ya no puedes añadir miembros.';
  }

  @override
  String sysLinkDeclined(String name) {
    return '$name es tu contacto y decidió no unirse a este grupo.';
  }

  @override
  String sysLinkCancelled(String name) {
    return 'Dejaste de esperar a que $name se una con tu enlace de invitación. Sigue siendo tu contacto.';
  }

  @override
  String get grpYouOwner => 'Tú (propietario)';

  @override
  String get grpOwner => 'propietario';

  @override
  String get grpChangeRole => 'Cambiar el rol';

  @override
  String get grpMakeAdmin => 'Hacer administrador';

  @override
  String get grpRemoveAdmin => 'Quitar como administrador';

  @override
  String get grpMakeOwner => 'Hacer propietario';

  @override
  String grpTransferTitle(String name) {
    return '¿Hacer propietario a $name?';
  }

  @override
  String grpTransferBody(String name) {
    return '$name será la única persona que pueda cambiar quiénes son los administradores. No puedes deshacerlo: solo el nuevo propietario puede devolvértelo.';
  }

  @override
  String get grpTransferKeepAdmin => 'Seguir como administrador';

  @override
  String get grpLeaveOwnerTitle => 'Eres el propietario de este grupo';

  @override
  String get grpLeaveOwnerBody =>
      'Si sales ahora, nadie podrá cambiar quiénes son los administradores. Los administradores podrán seguir añadiendo, quitando y cambiando el nombre. ¿Quieres nombrar antes a otro propietario?';

  @override
  String get grpLeaveAnyway => 'Salir de todos modos';

  @override
  String get grpTransferFirst => 'Transferir la propiedad';

  @override
  String get grpPickNewOwner => 'Nuevo propietario';

  @override
  String get grpRolesOnMainDevice =>
      'Los administradores y la propiedad del grupo solo se pueden cambiar en tu dispositivo principal.';

  @override
  String get grpAdminNotMember => 'administrador, ya no está en el grupo';

  @override
  String get grpLeaveOwnerBodyLinked =>
      'Si sales ahora, nadie podrá cambiar quiénes son los administradores. Los administradores aún podrán añadir, quitar y cambiar el nombre. Para ceder el grupo antes, usa tu dispositivo principal.';

  @override
  String grpTransferOldBuild(String name) {
    return 'Si $name aún tiene una versión de Z anterior a los administradores de grupo, nadie podrá cambiar quiénes son los administradores hasta que la actualice.';
  }

  @override
  String get grpInviteByLink => 'Invitar al grupo con un enlace';

  @override
  String get grpInviteByLinkNote =>
      'Funciona una sola vez, durante 24 horas. Quien lo abra primero será tu contacto y entrará en este grupo cuando acepte. El enlace en sí no dice nada del grupo.';

  @override
  String get stHandleSection => 'Alias';

  @override
  String get hdlYourHandle => 'Tu alias';

  @override
  String get hdlRowUnavailable => 'No disponible en esta versión';

  @override
  String get hdlRowLinked => 'Lo tiene tu dispositivo principal';

  @override
  String get hdlRowNone => 'Ninguno. Te añaden con tu código o una invitación';

  @override
  String hdlRowPending(String handle) {
    return '@$handle, pendiente de publicar';
  }

  @override
  String hdlRowHeld(String handle) {
    return '@$handle, sin publicar';
  }

  @override
  String hdlRowPaused(String handle) {
    return '@$handle, en pausa';
  }

  @override
  String hdlRowTaken(String handle) {
    return '@$handle, ya lo tiene otra persona';
  }

  @override
  String hdlRowLost(String handle) {
    return '@$handle, en manos de otra clave';
  }

  @override
  String get stHdlLogAddress => 'Dirección del servicio de alias';

  @override
  String get stHdlLogKey => 'Clave del servicio de alias';

  @override
  String get stHdlLogUrlTitle => 'URL del servicio de alias';

  @override
  String get stHdlLogKeyTitle => 'Clave pública del servicio de alias (base64)';

  @override
  String get hdlTitle => 'Tu alias';

  @override
  String get hdlUnavailable =>
      'Los alias aún no están disponibles. Esta versión de Z no tiene un servicio de alias configurado, así que no puedes reservar un alias ni buscar a nadie por uno.';

  @override
  String get hdlLinkedDevice =>
      'Solo tu dispositivo principal puede tener un alias. Resérvalo o gestiónalo allí; las personas que conozcas a través de él también aparecerán aquí.';

  @override
  String get hdlIntro =>
      'Un alias es un nombre por el que la gente puede encontrarte, como @alex.42. Es opcional, y puedes pausarlo o renunciar a él más adelante.';

  @override
  String get hdlWhatItShows =>
      'Cualquiera puede buscar un alias y enviarle una solicitud. Las solicitudes llegan a un buzón propio del alias, no a tu cuenta, y tú decides si aceptas cada una. Un alias es público: cualquiera puede saber que existe, y quienes gestionan el servicio de alias y el relé pueden ver la dirección de internet de tu dispositivo cuando lo reservas, lo consultas o lo usas.';

  @override
  String get hdlClaim => 'Reservar un alias';

  @override
  String get hdlRecover => 'Recuperar un alias';

  @override
  String get hdlNickLabel => 'Nombre';

  @override
  String get hdlNickHelp =>
      'De 3 a 20 letras, dígitos o _, empezando por una letra';

  @override
  String get hdlDigitsRandom => 'Dígitos al azar';

  @override
  String get hdlDigitsChoose => 'Elegir dígitos';

  @override
  String get hdlDigitsLabel => 'Dígitos (de 2 a 6)';

  @override
  String get hdlCheck => 'Comprobar';

  @override
  String hdlAvailable(String handle) {
    return '@$handle está libre.';
  }

  @override
  String hdlTaken(String handle) {
    return '@$handle ya está ocupado.';
  }

  @override
  String get hdlNoneFree =>
      'Todas las opciones al azar estaban ocupadas. Inténtalo de nuevo o elige los dígitos.';

  @override
  String get hdlTryOtherDigits => 'Probar otros dígitos';

  @override
  String hdlClaimThis(String handle) {
    return 'Reservar @$handle';
  }

  @override
  String get hdlCodeTitle => 'Código de recuperación de tu alias';

  @override
  String hdlCodeBody(String handle) {
    return 'Apúntalo y guárdalo en un lugar seguro. Se muestra una sola vez y Z no lo guarda. Es la única forma de recuperar @$handle si pierdes este dispositivo, y cualquiera que lo tenga puede quedarse con el alias, así que no lo compartas.';
  }

  @override
  String get hdlSemCode => 'Código de recuperación';

  @override
  String get hdlCodeWritten => 'Ya lo he apuntado';

  @override
  String get hdlCodeConfirmTitle => 'Vuelve a escribir el código';

  @override
  String get hdlCodeConfirmBody =>
      'Así comprobamos que lo has apuntado bien. No se publica nada hasta que lo hagas.';

  @override
  String get hdlCodeLabel => 'Código de recuperación';

  @override
  String get hdlCodeWrong => 'Ese no es el código que se mostró.';

  @override
  String hdlPendingBody(String handle, int minutes) {
    String _temp0 = intl.Intl.pluralLogic(
      minutes,
      locale: localeName,
      other: '@$handle se publicará en unos $minutes minutos.',
      one: '@$handle se publicará en un minuto, más o menos.',
      zero: '@$handle se publicará en un momento.',
    );
    return '$_temp0';
  }

  @override
  String get hdlPendingWhy =>
      'Se publica más tarde a propósito, en un momento al azar, para que la hora en que lo reservaste no se pueda relacionar con nada más que hiciste en Z. Mantén Z abierto hasta entonces.';

  @override
  String get hdlCancelClaim => 'Cancelar la reserva';

  @override
  String get hdlHeldBody =>
      'Esta reserva estaba pendiente de publicar cuando se hizo la copia de seguridad que restauraste. No se ha publicado desde este dispositivo.';

  @override
  String get hdlPublishNow => 'Publicar ahora';

  @override
  String hdlTakenBody(String handle) {
    return 'Otra persona reservó @$handle antes de que se publicara tu reserva. No se ha publicado nada a tu nombre.';
  }

  @override
  String get hdlChooseOther => 'Elegir otros dígitos';

  @override
  String get hdlDismiss => 'Descartar';

  @override
  String get hdlLiveBody =>
      'Aceptando solicitudes. Cada solicitud le cuesta algo de trabajo a quien la envía, así que no se pueden enviar en masa.';

  @override
  String get hdlNotVerification =>
      'Un alias no es una verificación: con quien conozcas a través de él, comparad los números de seguridad para estar seguros de quién es.';

  @override
  String get hdlRelayUnguarded =>
      'Tu relé es demasiado antiguo para proteger el buzón del alias: las solicitudes llegan sin ningún trabajo.';

  @override
  String get hdlIntroUnknown =>
      'El buzón del alias se cambió en otro dispositivo después de la copia que restauraste. Elige Buzón nuevo para recibir solicitudes aquí.';

  @override
  String get hdlCopy => 'Copiar alias';

  @override
  String get hdlCopied => 'Alias copiado';

  @override
  String hdlSemHandle(String handle) {
    return 'Tu alias, @$handle';
  }

  @override
  String get hdlPause => 'Pausar';

  @override
  String get hdlPauseHelp =>
      'Dejar de recibir solicitudes. A quien lo busque se le dirá que está en pausa.';

  @override
  String get hdlResume => 'Reanudar';

  @override
  String get hdlPausedBody =>
      'En pausa: a quien lo busque se le dice, y no puede enviar solicitudes.';

  @override
  String get hdlRotate => 'Buzón nuevo';

  @override
  String get hdlRotateHelp =>
      'Dar al alias un buzón nuevo, para cortar una oleada de solicitudes no deseadas. El alias sigue siendo el mismo y las solicitudes que ya esperan se quedan.';

  @override
  String get hdlDifficulty => 'Trabajo por solicitud';

  @override
  String get hdlDifficultyHelp =>
      'Cuánto trabajo le cuesta una solicitud a quien la envía. Más trabajo frena más spam y hace esperar más a todos los que preguntan.';

  @override
  String get hdlPow16 => 'Mínimo: una fracción de segundo';

  @override
  String get hdlPow18 => 'Bajo: menos de un segundo';

  @override
  String get hdlPow20 => 'Normal: un segundo, unos pocos en un móvil lento';

  @override
  String get hdlPow22 => 'Alto: varios segundos';

  @override
  String get hdlPow24 => 'Máximo: hasta un minuto en un móvil lento';

  @override
  String get hdlRetire => 'Renunciar al alias';

  @override
  String hdlRetireConfirmTitle(String handle) {
    return '¿Renunciar a @$handle?';
  }

  @override
  String get hdlRetireConfirmBody =>
      'Nadie podrá contactarte a través de él, y este dispositivo olvida sus claves. El nombre se queda en el registro público y nadie más puede reservarlo; solo su código de recuperación puede devolvértelo.';

  @override
  String hdlLostBody(String handle) {
    return '@$handle está ahora en manos de otra clave: se usó su código de recuperación. Este dispositivo ya no puede cambiarlo.';
  }

  @override
  String get hdlForget => 'Olvidarlo';

  @override
  String get hdlRecoverTitle => 'Recuperar un alias';

  @override
  String get hdlRecoverBody =>
      'Escribe el alias y su código de recuperación. El alias pasa a esta cuenta con claves nuevas y recibirás un código nuevo.';

  @override
  String get hdlHandleLabel => 'Alias';

  @override
  String get hdlRecoverAction => 'Recuperar';

  @override
  String hdlRecovered(String handle) {
    return '@$handle vuelve a ser tuyo.';
  }

  @override
  String get hdlBadEmpty => 'Escribe un alias, como alex.42.';

  @override
  String hdlBadCharacter(String char) {
    return '“$char” no puede ir en un alias. Usa de la a a la z, del 0 al 9 y _.';
  }

  @override
  String get hdlBadMissingDigits =>
      'Añade los dígitos tras un punto, como alex.42.';

  @override
  String get hdlBadDigitsNotDigits => 'Tras el punto solo van dígitos.';

  @override
  String get hdlBadReserved => 'Ese nombre está reservado.';

  @override
  String get hdlBadNickShort => 'El nombre necesita al menos 3 caracteres.';

  @override
  String get hdlBadNickLong =>
      'El nombre puede tener como mucho 20 caracteres.';

  @override
  String get hdlBadNickStart => 'El nombre debe empezar por una letra.';

  @override
  String get hdlBadNickDoubleUnderscore =>
      'El nombre no puede tener dos _ seguidos.';

  @override
  String get hdlBadNickEndUnderscore => 'El nombre no puede terminar en _.';

  @override
  String get hdlBadDigitsShort => 'Un alias tiene al menos 2 dígitos.';

  @override
  String get hdlBadDigitsLong => 'Un alias tiene como mucho 6 dígitos.';

  @override
  String get hdlErrUnreachable =>
      'No se pudo contactar con el servicio de alias. Inténtalo más tarde.';

  @override
  String get hdlErrBadAnswer =>
      'La respuesta del servicio de alias no superó la comprobación, así que no se usó nada de lo que dijo.';

  @override
  String get hdlErrRefused => 'El servicio de alias lo rechazó.';

  @override
  String get hdlErrTaken => 'Ese alias ya lo tiene otra persona.';

  @override
  String get hdlErrChanged =>
      'El alias cambió mientras lo hacías. Inténtalo de nuevo.';

  @override
  String get hdlErrLost => 'Ese alias está ahora en manos de otra clave.';

  @override
  String get hdlErrNotConnected =>
      'Sin conexión con el relé. Inténtalo cuando tengas conexión.';

  @override
  String get hdlErrPowRefused =>
      'El relé no aceptó la prueba de trabajo de la solicitud. No se entregó nada; inténtalo más tarde.';

  @override
  String get hdlErrRelayRefused => 'El relé rechazó la solicitud.';

  @override
  String get hdlErrPaused =>
      'Ese alias está en pausa, así que no se envió nada.';

  @override
  String get hdlErrNotClaimed => 'Nadie tiene ese alias.';

  @override
  String get hdlErrWrongCode => 'Ese código no recupera este alias.';

  @override
  String get hdlErrBadCode =>
      'Eso no es un código de recuperación. Revísalo e inténtalo de nuevo.';

  @override
  String get hdlErrBackupCode =>
      'Ese es un código de recuperación de copia de seguridad. Un alias tiene su propio código, que empieza por ZHR.';

  @override
  String get hdlErrAlreadyHasOne => 'Esta cuenta ya tiene un alias.';

  @override
  String get hdlErrNoHandle => 'Aquí no hay ningún alias que cambiar.';

  @override
  String get addHandle => 'Alias';

  @override
  String get hdlFindHelp =>
      'Si alguien te dijo su alias, búscalo aquí y envíale una solicitud. Esa persona decide si la acepta.';

  @override
  String get hdlFindLabel => 'Su alias';

  @override
  String get hdlFindHint => '@ana.42';

  @override
  String get hdlFind => 'Buscar';

  @override
  String get hdlLookingUp => 'Buscando…';

  @override
  String hdlFound(String handle) {
    return 'Encontrado: @$handle.';
  }

  @override
  String get hdlFoundNote =>
      'Un alias no es una verificación. Si acepta, comparad los números de seguridad para estar seguros de quién es.';

  @override
  String get hdlSendRequest => 'Enviar solicitud';

  @override
  String get hdlSending => 'Enviando. Esto tarda unos segundos a propósito…';

  @override
  String hdlRequestSent(String handle) {
    return 'Solicitud enviada a @$handle. Si la acepta, aparecerá en tus chats.';
  }

  @override
  String hdlNotFound(String handle) {
    return 'Nadie ha reservado @$handle.';
  }

  @override
  String hdlFoundPaused(String handle) {
    return '@$handle está en pausa: ahora mismo no acepta solicitudes.';
  }

  @override
  String hdlFoundInvalid(String handle) {
    return 'La respuesta del servicio de alias para @$handle no superó la comprobación. No se envió nada.';
  }

  @override
  String get hdlFoundOwn => 'Ese es tu propio alias.';

  @override
  String hdlSemFound(String handle) {
    return 'Alias @$handle';
  }

  @override
  String get hdlWaiting => 'Esperando respuesta';

  @override
  String get hdlForgetRequest => 'Olvidar';

  @override
  String requestsVia(String handle) {
    return 'A través de @$handle';
  }

  @override
  String sysHandleAccepted(String handle) {
    return '@$handle aceptó. Comparad los números de seguridad para verificar.';
  }
}
