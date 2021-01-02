package my.diploma.client.bob.services

import cats.Monad
import cats.effect.{Sync, Timer}
import my.diploma.common.MessagesClient
import org.whispersystems.libsignal.state.{PreKeyBundle, SignedPreKeyRecord}
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore
import org.whispersystems.libsignal.util.KeyHelper
import org.whispersystems.libsignal.{IdentityKey, SessionBuilder, SessionCipher, SignalProtocolAddress}

import scala.jdk.CollectionConverters._
import cats.syntax.flatMap._
import cats.syntax.functor._
import my.diploma.common.models.PreKeyBundleForClient
import org.whispersystems.libsignal.ecc.Curve
import org.whispersystems.libsignal.protocol.{PreKeySignalMessage, SignalMessage}

import scala.concurrent.duration.DurationInt

trait Processor[F[_]] { def run: F[Unit] }

object Processor {

  def create[F[_]: Sync: Timer](messagesClient: MessagesClient[F]): Processor[F] =
    new Impl[F](messagesClient)

  final private class Impl[F[_]: Timer](messagesClient: MessagesClient[F])(implicit F: Sync[F]) extends Processor[F] {

    val identityKeyPair = KeyHelper.generateIdentityKeyPair
    val registrationId  = KeyHelper.generateRegistrationId(false)
    val preKeys         = KeyHelper.generatePreKeys(1, 1).asScala.toList

    val signedPreKey: SignedPreKeyRecord =
      KeyHelper.generateSignedPreKey(identityKeyPair, 5)

    val bobStore = new InMemorySignalProtocolStore(identityKeyPair, registrationId)

    bobStore.storeSignedPreKey(5, signedPreKey)
    preKeys.take(1).foreach(preKey => bobStore.storePreKey(preKey.getId, preKey))

    val preKeyBundle =
      new PreKeyBundle(
        1,
        1,
        preKeys.head.getId,
        preKeys.head.getKeyPair.getPublicKey,
        5,
        signedPreKey.getKeyPair.getPublicKey,
        signedPreKey.getSignature,
        bobStore.getIdentityKeyPair.getPublicKey
      )

    val ALICE_ADDRESS = new SignalProtocolAddress("+14159998888", 1)

    val bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS)

    val bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS)

    def run: F[Unit] =
      for {
        _                     <- messagesClient.publishPreKeyBundle(preKeyBundle) //1
        initialMessage        <- messagesClient.receiveInitialMessage //4
        alicaPreKeyBundle     <- makeAlicePreKeyBundle(initialMessage.preKeyBundleForClient)
        _                     <- F.delay(bobSessionBuilder.process(alicaPreKeyBundle))
        decryptedMessageBytes <- F.delay(bobSessionCipher.decrypt(new PreKeySignalMessage(initialMessage.message)))
        decryptedMessage = new String(decryptedMessageBytes)
        _               <- F.delay(println(s"[BOB]: $decryptedMessage."))
        bobFirstMessage <- F.delay(bobSessionCipher.encrypt("This is the first Bob's message!".getBytes()))
        _               <- messagesClient.sendMessageToAlice(bobFirstMessage.serialize()) //5
        _               <- communication
      } yield ()

    def makeAlicePreKeyBundle(preKeyBundleForClient: PreKeyBundleForClient): F[PreKeyBundle] =
      F.delay(
        new PreKeyBundle(
          preKeyBundleForClient.registrationId,
          preKeyBundleForClient.deviceId,
          preKeyBundleForClient.preKeyId,
          Curve.decodePoint(preKeyBundleForClient.preKeyPublic, 0),
          preKeyBundleForClient.signedPreKeyId,
          Curve.decodePoint(preKeyBundleForClient.SPK, 0),
          preKeyBundleForClient.Signature,
          new IdentityKey(preKeyBundleForClient.IK, 0)
        )
      )

    def communication: F[Unit] =
      messagesClient.receiveMessageToBob
        .map(new SignalMessage(_))
        .flatMap { message =>
          F.delay(bobSessionCipher.decrypt(message)).flatMap { decrypted =>
            F.delay(println(s"[ALICE]: ${new String(decrypted)}"))
          }
        }
        .flatTap { _ =>
          val uniqueId        = scala.util.Random.nextInt()
          val nextBobsMessage = s"This is the next Bob's message with unique id: $uniqueId"
          F.delay(println(s"[BOB]: $nextBobsMessage")) >>
          F.delay(bobSessionCipher.encrypt(nextBobsMessage.getBytes()))
            .flatTap(_ => Timer[F].sleep(5.seconds))
            .flatMap(msg => messagesClient.sendMessageToAlice(msg.serialize()))
        }
        .flatMap(_ => communication)
  }
}
