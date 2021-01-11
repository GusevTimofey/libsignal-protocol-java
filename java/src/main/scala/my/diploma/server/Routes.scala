package my.diploma.server

import cats.effect.Concurrent
import my.diploma.common.models.{InitialMessage, PreKeyBundleForClient}
import org.http4s.HttpRoutes
import org.http4s.dsl.Http4sDsl
import org.http4s.util.CaseInsensitiveString
import io.circe.syntax._
import cats.syntax.either._
import cats.syntax.functor._
import cats.syntax.flatMap._
import cats.syntax.option._
import io.circe.parser._
import org.http4s.circe._
import org.http4s.server.middleware.Logger

trait Routes[F[_]] {
  val routes: HttpRoutes[F]
}

object Routes {

  def create[F[_]: Concurrent]: Routes[F] = new Impl[F]

  final private class Impl[F[_]: Concurrent] extends Http4sDsl[F] with Routes[F] {
    val routes: HttpRoutes[F] = logRoutes

    var preKeysBundle: List[PreKeyBundleForClient] = List.empty
    var initialMessages: List[InitialMessage]      = List.empty
    var messagesForBob: List[String]               = List.empty
    var messagesForAlice: List[String]             = List.empty

    def logRoutes =
      Logger.httpRoutes(
        logHeaders = true,
        logBody    = true,
        logAction  = ((str: String) => Concurrent[F].delay(println(str))).some
      )(allRoutes)

    def allRoutes = HttpRoutes.of[F] {
      case r @ POST -> Root / "publishPreKeys" =>
        val rawHeader = r.headers.get(CaseInsensitiveString("preKeyBundle")).get.value
        val bundle    = parse(rawHeader).leftMap(throw _).merge.as[PreKeyBundleForClient].leftMap(throw _).merge
        preKeysBundle ::= bundle
        println(s"Server got pre key bundle.")
        Concurrent[F].unit.map(_.asJson).flatMap(Ok(_))
      case r @ GET -> Root / "fetchPreKeys" =>
        println(s"Server got fetchPreKeys.")
        Ok(preKeysBundle.head.asJson)
      case r @ POST -> Root / "sendInitialMessage" =>
        println(s"Server got sendInitialMessage.")
        val rawHeader      = r.headers.get(CaseInsensitiveString("initialMessage")).get.value
        val initialMessage = parse(rawHeader).leftMap(throw _).merge.as[InitialMessage].leftMap(throw _).merge
        initialMessages ::= initialMessage
        Concurrent[F].unit.map(_.asJson).flatMap(Ok(_))
      case r @ GET -> Root / "receiveInitialMessage" =>
        println(s"Server got receiveInitialMessage.")
        Ok(initialMessages.head.asJson)

      case r @ POST -> Root / "sendMessageToBob" =>
        println(s"Server got sendMessageToBob.")
        val rawHeader = r.headers.get(CaseInsensitiveString("sendMessage")).get.value
        messagesForBob ::= rawHeader
        Concurrent[F].unit.map(_.asJson).flatMap(Ok(_))

      case r @ GET -> Root / "getMessageToBob" =>
        println(s"Server got getMessageToBob.")
        val msg = messagesForBob.head
        messagesForBob = messagesForBob.drop(1)
        Ok(msg.asJson)

      case r @ POST -> Root / "sendMessageToAlice" =>
        println(s"Server got sendMessageToAlice.")
        val rawHeader = r.headers.get(CaseInsensitiveString("sendMessage")).get.value
        messagesForAlice ::= rawHeader
        Concurrent[F].unit.map(_.asJson).flatMap(Ok(_))

      case r @ GET -> Root / "getMessageToAlice" =>
        println(s"Server got getMessageToAlice.")
        val msg = messagesForAlice.head
        messagesForAlice = messagesForAlice.drop(1)
        Ok(msg.asJson)
    }
  }
}
