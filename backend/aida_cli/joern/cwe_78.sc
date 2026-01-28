import io.shiftleft.semanticcpg.language.*
import io.joern.dataflowengineoss.language.*

def sinkPattern = "(?i)^(system|popen|execl|execv|execle|execve|execvp|WinExec|ShellExecute(Ex)?|CreateProcess(A|W)?)$"

def commandArgsFor(callId: Long, callName: String) = {
  if (callName == "system") cpg.call.id(callId).argument(1)
  else if (callName == "popen") cpg.call.id(callId).argument(1)
  else if (callName.startsWith("exec")) cpg.call.id(callId).argument(1)
  else if (callName.startsWith("createprocess")) cpg.call.id(callId).argument(2)
  else if (callName.startsWith("shellexecute")) cpg.call.id(callId).argument(2)
  else if (callName == "winexec") cpg.call.id(callId).argument(1)
  else cpg.call.id(callId).argument
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
  val mf = Option(c.methodFullName).getOrElse("")
  val ln = c.lineNumber.getOrElse(-1)
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
  val sinks = cpg.call.name(sinkPattern).toList
  val findings = sinks.flatMap { s =>
    val sinkName = s.name.toLowerCase
    val cmdArgs = commandArgsFor(s.id, sinkName)
    val flowsPretty = cmdArgs.reachableByFlows(sourceBufs).p
    if (flowsPretty.nonEmpty) {
      val location = formatLoc(s)
      val flowStrings = flowsPretty.toList
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
