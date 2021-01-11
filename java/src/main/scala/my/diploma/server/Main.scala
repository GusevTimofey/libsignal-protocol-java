package my.diploma.server

import cats.effect.ExitCode
import monix.eval.{Task, TaskApp}

object Main extends TaskApp {

  def run(args: List[String]): Task[ExitCode] =
    MakeServer.create[Task].make.compile.drain.as(ExitCode.Success)
}
