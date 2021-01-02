package my.diploma.client.bob

import cats.effect.ExitCode
import monix.eval.{Task, TaskApp}
import my.diploma.client.bob.services.Processor
import my.diploma.common.MessagesClient
import org.http4s.client.blaze.BlazeClientBuilder

import scala.concurrent.ExecutionContext

object Main extends TaskApp {

  def run(args:  List[String]): Task[ExitCode] =
    BlazeClientBuilder[Task](ExecutionContext.global)
      .resource.use { client =>
      println(s"Run Bob")
      val myClient = MessagesClient.create[Task](client)
      Processor.create[Task](myClient).run.as(ExitCode.Success)
    }
}
