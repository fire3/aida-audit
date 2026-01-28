import io.shiftleft.semanticcpg.language.*
import io.joern.dataflowengineoss.language.*
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths

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
  val entries = sinks.flatMap { s =>
    val sinkName = s.name.toLowerCase
    val cmdArgs = commandArgsFor(s.id, sinkName)
    val sources = cmdArgs.reachableBy(sourceBufs).toList
    if (sources.nonEmpty) {
      val location = formatLoc(s)
      val sinkJson = cpg.call.id(s.id).toJson
      val sourcesJson = sources.toJson
      val entry = s"""{"cwe":"CWE-78","sink":$sinkJson,"location":${jsonString(location)},"sources":$sourcesJson}"""
      List(entry)
    } else {
      List()
    }
  }
  entries.mkString("[", ",", "]")
}

@main def exec(cpgFile: String, outputFile: String = "") = {
  importCpg(cpgFile)
  val json = runJson()
  if (outputFile != null && outputFile.nonEmpty) {
    Files.write(Paths.get(outputFile), json.getBytes(StandardCharsets.UTF_8))
  } else {
    println(json)
  }
}
