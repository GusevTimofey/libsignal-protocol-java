package my.diploma.client.alice.services

import cats.effect.{Sync, Timer}
import my.diploma.common.MessagesClient
import org.whispersystems.libsignal.state.{PreKeyBundle, SignedPreKeyRecord}
import org.whispersystems.libsignal.util.KeyHelper

import scala.jdk.CollectionConverters._
import cats.syntax.flatMap._
import cats.syntax.functor._
import my.diploma.common.models.{InitialMessage, PreKeyBundleForClient}
import org.whispersystems.libsignal.ecc.Curve
import org.whispersystems.libsignal.protocol.SignalMessage
import org.whispersystems.libsignal.{IdentityKey, SessionBuilder, SessionCipher, SignalProtocolAddress}
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore

import scala.concurrent.duration.DurationInt

trait Processor[F[_]] {
  def run: F[Unit]
}

object Processor {

  def create[F[_]: Sync: Timer](messagesClient: MessagesClient[F]): Processor[F] =
    new Impl[F](messagesClient)

  final private class Impl[F[_]: Timer](messagesClient: MessagesClient[F])(implicit F: Sync[F]) extends Processor[F] {

    val identityKeyPair = KeyHelper.generateIdentityKeyPair
    val registrationId  = KeyHelper.generateRegistrationId(false)
    val preKeys         = KeyHelper.generatePreKeys(1, 1).asScala.toList

    val signedPreKey: SignedPreKeyRecord =
      KeyHelper.generateSignedPreKey(identityKeyPair, 5)

    val aliceStore = new InMemorySignalProtocolStore(identityKeyPair, registrationId)

    aliceStore.storeSignedPreKey(5, signedPreKey)
    preKeys.take(1).foreach(preKey => aliceStore.storePreKey(preKey.getId, preKey))

    val preKeyBundle =
      new PreKeyBundle(
        1,
        1,
        preKeys.head.getId,
        preKeys.head.getKeyPair.getPublicKey,
        5,
        signedPreKey.getKeyPair.getPublicKey,
        signedPreKey.getSignature,
        aliceStore.getIdentityKeyPair.getPublicKey
      )

    val BOB_ADDRESS = new SignalProtocolAddress("+14151231234", 1)

    val aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS)

    val aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS)

    def run: F[Unit] =
      for {
        bobsBundleForClient <- messagesClient.fetchPreKeyBundle //2
        bobsBundle          <- makeBobPreKeyBundle(bobsBundleForClient)
        _                   <- F.delay(aliceSessionBuilder.process(bobsBundle))
        messageForBob       <- F.delay(aliceSessionCipher.encrypt("This is the initial message from Alice".getBytes()))
        initialMessage = InitialMessage(
                           PreKeyBundleForClient(
                             preKeyBundle.getRegistrationId,
                             preKeyBundle.getDeviceId,
                             preKeyBundle.getPreKey.serialize(),
                             preKeyBundle.getPreKeyId,
                             preKeyBundle.getSignedPreKeyId,
                             preKeyBundle.getSignedPreKey.serialize(),
                             preKeyBundle.getSignedPreKeySignature,
                             preKeyBundle.getIdentityKey.serialize()
                           ),
                           messageForBob.serialize()
                         )
        _ <- messagesClient.sendInitialMessage(initialMessage) //3
        _ <- communication
      } yield ()

    def makeBobPreKeyBundle(preKeyBundleForClient: PreKeyBundleForClient): F[PreKeyBundle] =
      F.delay {
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
      }

    def communication: F[Unit] =
      messagesClient.receiveMessageToAlice
        .map(new SignalMessage(_))
        .flatMap { message =>
          F.delay(aliceSessionCipher.decrypt(message)).flatMap { decrypted =>
            F.delay(println(s"[BOB]: ${new String(decrypted)}"))
          }
        }
        .flatTap { _ =>
          val uniqueId        = scala.util.Random.nextInt()
          val nextBobsMessage = s"This is the next Alice's message with unique id: $uniqueId"
          F.delay(println(s"[ALICE]: $nextBobsMessage")) >>
          F.delay(aliceSessionCipher.encrypt(nextBobsMessage.getBytes()))
            .flatTap(_ => Timer[F].sleep(5.seconds))
            .flatMap(msg => messagesClient.sendMessageToBob(msg.serialize()))
        }
        .flatMap(_ => communication)
  }
}
