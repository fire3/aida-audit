import io.shiftleft.semanticcpg.language.*
import io.joern.dataflowengineoss.language.*

def sinkPattern = "(?i)^(system|popen|execl|execv|execle|execve|execvp|WinExec|ShellExecute(Ex)?|CreateProcess(A|W)?)$"

def commandArgsFor(c: io.shiftleft.codepropertygraph.generated.nodes.Call) = {
  val n = c.name.l.headOption.getOrElse("").toLowerCase
  if (n == "system") c.argument(1)
  else if (n == "popen") c.argument(1)
  else if (n.startsWith("exec")) c.argument(1)
  else if (n.startsWith("createprocess")) c.argument(2)
  else if (n.startsWith("shellexecute")) c.argument(2)
  else if (n == "winexec") c.argument(1)
  else c.argument
}

def sourceBufs = {
  val recvBuf = cpg.call.name("(?i)^(recv|recvfrom|WSARecv|WSARecvFrom)$").argument(2)
  val readBuf = cpg.call.name("(?i)^(read|fread)$").argument(2)
  val fgetsBuf = cpg.call.name("(?i)^(fgets|getline|gets)$").argument(1)
  val winReadBuf = cpg.call.name("(?i)^(ReadFile|InternetReadFile|HttpReceiveHttpRequest)$").argument(2)
  val argvIds = cpg.identifier.name("(?i)^argv$")
  val envVals = cpg.call.name("(?i)^getenv$").argument(1)
  recvBuf ++ readBuf ++ fgetsBuf ++ winReadBuf ++ argvIds ++ envVals
}

def formatLoc(c: io.shiftleft.codepropertygraph.generated.nodes.Call) = {
  val mf = c.methodFullName.l.headOption.getOrElse("")
  val ln = c.lineNumber.l.headOption.getOrElse(-1)
  s"$mf:$ln"
}

def escapeJson(s: String) = {
  s.replace("\\", "\\\\")
    .replace("\"", "\\\"")
    .replace("\r", "\\r")
    .replace("\n", "\\n")
    .replace("\t", "\\t")
}

def jsonString(s: String) = "\"" + escapeJson(s) + "\""

def runJson() = {
  val sinks = cpg.call.name(sinkPattern).l
  val findings = sinks.flatMap { s =>
    val cmdArgs = commandArgsFor(s)
    val flows = cmdArgs.reachableBy(sourceBufs).flows
    if (flows.nonEmpty) {
      val sinkName = s.name.l.headOption.getOrElse("")
      val location = formatLoc(s)
      val flowStrings = flows.map(_.toString)
      List((sinkName, location, flowStrings))
    } else {
      List()
    }
  }
  val jsonEntries = findings.map { case (sinkName, location, flowStrings) =>
    val flowsJson = flowStrings.map(jsonString).mkString("[", ",", "]")
    s"""{"cwe":"CWE-78","sink":${jsonString(sinkName)},"location":${jsonString(location)},"flows":$flowsJson}"""
  }
  jsonEntries.mkString("[", ",", "]")
}

@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println(runJson())
}
