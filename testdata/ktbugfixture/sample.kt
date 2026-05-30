// TODO: handle nulls properly
fun process(name: String?, cmd: String) {
    val len = name!!.length
    Runtime.getRuntime().exec(cmd)
    println(len)
}
