object Sample {
  // TODO: remove null and unsafe casts
  def process(x: Any): String = {
    val name: String = null
    val n = x.asInstanceOf[Int]
    s"$name-$n"
  }
}
