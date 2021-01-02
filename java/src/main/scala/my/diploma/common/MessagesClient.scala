package my.diploma.common

import cats.Monad
import cats.effect.{Sync, Timer}
import my.diploma.common.models.{InitialMessage, PreKeyBundleForClient}
import org.http4s.{EntityDecoder, Header, Headers, InvalidMessageBodyFailure, Method, Request, Uri}
import org.http4s.client.Client
import io.circe._
import io.circe.parser._
import org.http4s.circe.CirceEntityDecoder._
import org.whispersystems.libsignal.state.PreKeyBundle
import cats.syntax.applicativeError._
import cats.syntax.flatMap._
import cats.syntax.functor._
import cats.syntax.either._
import io.circe.syntax._
import my.diploma.common.base64.{fromBase64, toBase64Url}

import scala.concurrent.duration.DurationInt

trait MessagesClient[F[_]] {
  def publishPreKeyBundle(bundle: PreKeyBundle): F[Unit]
  def fetchPreKeyBundle: F[PreKeyBundleForClient]
  def sendInitialMessage(message: InitialMessage): F[Unit]
  def receiveInitialMessage: F[InitialMessage]
  def sendMessageToBob(message: Array[Byte]): F[Unit]
  def sendMessageToAlice(message: Array[Byte]): F[Unit]
  def receiveMessageToBob: F[Array[Byte]]
  def receiveMessageToAlice: F[Array[Byte]]
}

object MessagesClient {
  def create[F[_]: Sync: Timer](client: Client[F]): MessagesClient[F] =
    new Impl[F](client)

  private final class Impl[F[_]: Sync: Timer](client: Client[F]) extends MessagesClient[F] {

    def publishPreKeyBundle(bundle: PreKeyBundle): F[Unit] = {
      val string = PreKeyBundleForClient(
        bundle.getRegistrationId,
        bundle.getDeviceId,
        bundle.getPreKey.serialize(),
        bundle.getPreKeyId,
        bundle.getSignedPreKeyId,
        bundle.getSignedPreKey.serialize(),
        bundle.getSignedPreKeySignature,
        bundle.getIdentityKey.serialize()
      ).asJson.noSpaces
      client
        .expect[Unit](Request[F](Method.POST, Uri.unsafeFromString("http://0.0.0.0:8081/publishPreKeys"), headers =
          Headers.of(
            Header("preKeyBundle", string)
          )
        ))
        .handleErrorWith { err: Throwable =>
          Sync[F].delay(println(s"Error in publishPreKeyBundle: ${err.getMessage}"))
            .flatMap(_ => Timer[F].sleep(2.seconds))
            .flatMap(_ => publishPreKeyBundle(bundle))
        }
}

    def fetchPreKeyBundle: F[PreKeyBundleForClient] =
      client.expect[PreKeyBundleForClient](Request[F](Method.GET, Uri.unsafeFromString("http://0.0.0.0:8081/fetchPreKeys")))
        .handleErrorWith { err: Throwable =>
          Sync[F].delay(println(s"Error in fetchPreKeyBundle: ${err.getMessage}"))
            .flatMap(_ => Timer[F].sleep(2.seconds))
            .flatMap(_ => fetchPreKeyBundle)
        }

    def sendInitialMessage(message: InitialMessage): F[Unit] =
      client
      .expect[Unit](Request[F](Method.POST, Uri.unsafeFromString("http://0.0.0.0:8081/sendInitialMessage"), headers =
        Headers.of(
          Header("initialMessage", message.asJson.noSpaces)
        )
      ))
      .handleErrorWith { err: Throwable =>
        Sync[F].delay(println(s"Error in sendInitialMessage: ${err.getMessage}"))
          .flatMap(_ => Timer[F].sleep(2.seconds))
          .flatMap(_ => sendInitialMessage(message))
      }

    def receiveInitialMessage: F[InitialMessage] =
      client.expect[InitialMessage](Request[F](Method.GET, Uri.unsafeFromString("http://0.0.0.0:8081/receiveInitialMessage")))
        .handleErrorWith { err: Throwable =>
          Sync[F].delay(println(s"Error in receiveInitialMessage: ${err.getMessage}"))
            .flatMap(_ => Timer[F].sleep(2.seconds))
            .flatMap(_ => receiveInitialMessage)
        }

    def sendMessageToBob(message: Array[Byte]): F[Unit] = {
    val header = Header("sendMessage", message.asJson.noSpaces)
    //println(s"sendMessage sendMessageToBob: ${header.name} -> ${header.value}")
    client
      .expect[Unit](
        Request[F](Method.POST, Uri.unsafeFromString("http://0.0.0.0:8081/sendMessageToBob"),
          headers = Headers.of(header)
        )
      )
      .handleErrorWith { err: Throwable =>
        Sync[F].delay(println(s"Error in sendMessage: ${err.getMessage}"))
          .flatMap(_ => Timer[F].sleep(2.seconds))
          .flatMap(_ => sendMessageToBob(message))
      }
      }

    def sendMessageToAlice(message: Array[Byte]): F[Unit] =
    {
      val header = Header("sendMessage", message.asJson.noSpaces)
      //println(s"sendMessage sendMessageToAlice: ${header.name} -> ${header.value}")
      client
        .expect[Unit](
          Request[F](Method.POST, Uri.unsafeFromString("http://0.0.0.0:8081/sendMessageToAlice"),
            headers = Headers.of(header)
          )
        )
        .handleErrorWith { err: Throwable =>
          Sync[F].delay(println(s"Error in sendMessage: ${err.getMessage}"))
            .flatMap(_ => Timer[F].sleep(2.seconds))
            .flatMap(_ => sendMessageToAlice(message))
        }
    }

    def receiveMessageToBob: F[Array[Byte]] =
      client.expect[String](Request[F](Method.GET, Uri.unsafeFromString("http://0.0.0.0:8081/getMessageToBob")))
        //.flatTap(str => Sync[F].delay(println(s"Received: ${str}")))
        .map(parse(_).flatMap(_.as[Array[Byte]]).leftMap(throw _).merge)
        //.flatTap(str => Sync[F].delay(println(s"parsed: ${str.mkString("Array(", ", ", ")")}")))
        .handleErrorWith { err: Throwable =>
          Sync[F].delay(println(s"Error in receiveMessage: ${err.getMessage}"))
            .flatMap(_ => Timer[F].sleep(2.seconds))
            .flatMap(_ => receiveMessageToBob)
        }

    def receiveMessageToAlice: F[Array[Byte]] =
      client.expect[String](Request[F](Method.GET, Uri.unsafeFromString("http://0.0.0.0:8081/getMessageToAlice")))
        //.flatTap(str => Sync[F].delay(println(s"Received: ${str}")))
        .map(parse(_).flatMap(_.as[Array[Byte]]).leftMap(throw _).merge)
        //.flatTap(str => Sync[F].delay(println(s"parsed: ${str.mkString("Array(", ", ", ")")}")))
        .handleErrorWith { err: Throwable =>
          Sync[F].delay(println(s"Error in receiveMessage: ${err.getMessage}"))
            .flatMap(_ => Timer[F].sleep(2.seconds))
            .flatMap(_ => receiveMessageToAlice)
        }

  }
}