package com.mchange.pimento

/**
 *  Erasables are NOT in general thread-safe, so should only be used in single-thread contexts
 */
object Erasable:
  given byteArrayIsErasable : Erasable[Array[Byte]] with
    def erase( thing : Array[Byte] ) : Unit =
      val len = thing.length
      var i = 0
      while i < len do
        thing(i) = 0
        i += 1
      end while

  given charArrayIsErasable : Erasable[Array[Char]] with
    def erase( thing : Array[Char] ) : Unit =
      val len = thing.length
      var i = 0
      while i < len do
        thing(i) = 0
        i += 1
      end while

  extension[T : Erasable]( thing : T )
    def erase() = summon[Erasable[T]].erase( thing )

trait Erasable[T]:
  def erase( thing : T ) : Unit

