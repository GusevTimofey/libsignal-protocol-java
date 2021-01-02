package my.diploma.server

import cats.effect.{ConcurrentEffect, ExitCode, Timer}
import fs2.Stream
import org.http4s.server.blaze.BlazeServerBuilder
import org.http4s.implicits._
import scala.concurrent.ExecutionContext

trait MakeServer[F[_]] {
  def make: Stream[F, ExitCode]
}

object MakeServer {

  def create[F[_]: ConcurrentEffect: Timer]: MakeServer[F] = new Impl[F]

  final private class Impl[F[_]: ConcurrentEffect: Timer] extends MakeServer[F] {

    def make: Stream[F, ExitCode] =
      BlazeServerBuilder
        .apply(ExecutionContext.global)
        .bindHttp(8081, "0.0.0.0")
        .withHttpApp(Routes.create[F].routes.orNotFound)
        .serve
  }

}
