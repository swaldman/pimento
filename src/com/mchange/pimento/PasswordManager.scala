package com.mchange.pimento

object PasswordManager:
  trait Standard[PW <: Erasable, SC <: Erasable, T] extends PasswordManager[PW, T]:
    def storeFor( username : String, storableCredential : SC, identity : T ) : Unit
    def storedCredentialAndIdentity( username : String ) : Option[( SC, T )]

    def createStorableCredential( password : PW ) : SC
    def checkAgainstCredential( password : PW, storedCredential : SC ) : Boolean

    def set( username : String, password : PW, identity : T ) : Unit =
      val storableCredential = createStorableCredential( password )
      try
        storeFor( username, storableCredential, identity )
      finally
        storableCredential.erase()

    def authenticate( username : String, password : PW ) : Option[T] =
      val tup = storedCredentialAndIdentity( username )
      tup.flatMap: ( storedCredential, identity ) =>
        try
          if checkAgainstCredential( password, storedCredential ) then Some(identity) else None
        finally
          storedCredential.erase()
  end Standard

  object FavreBCrypt:
    object LongPasswordStrategy:
      import at.favre.lib.crypto.bcrypt.{BCrypt, LongPasswordStrategy, LongPasswordStrategies}
      trait Strict:
        this : PasswordManager.FavreBCrypt[?,?,?] =>
        override def longPasswordStrategy( bv : BCrypt.Version )  : LongPasswordStrategy = LongPasswordStrategies.strict( bv )
      trait Truncate:
        this : PasswordManager.FavreBCrypt[?,?,?] =>
        override def longPasswordStrategy( bv : BCrypt.Version )  : LongPasswordStrategy = LongPasswordStrategies.truncate( bv )
      trait HashSha512:
        this : PasswordManager.FavreBCrypt[?,?,?] =>
        override def longPasswordStrategy( bv : BCrypt.Version )  : LongPasswordStrategy = LongPasswordStrategies.hashSha512( bv )
    trait ByteArray[T]( val costFactor : Int ) extends FavreBCrypt[Erasable.ByteArray,Erasable.ByteArray,T]:
      def createStorableCredential( password : Erasable.ByteArray ) : Erasable.ByteArray =
        Erasable.ByteArray( hasher.hash( costFactor, password.value ) )
      def checkAgainstCredential( password : Erasable.ByteArray, storedCredential : Erasable.ByteArray ) : Boolean =
      verifier.verify( password.value, storedCredential.value ).verified
    trait CharArray[T]( val costFactor : Int ) extends FavreBCrypt[Erasable.CharArray,Erasable.CharArray,T]:
      def createStorableCredential( password : Erasable.CharArray ) : Erasable.CharArray =
        Erasable.CharArray( hasher.hashToChar( costFactor, password.value ) )
      def checkAgainstCredential( password : Erasable.CharArray, storedCredential : Erasable.CharArray ) : Boolean =
        verifier.verify( password.value, storedCredential.value ).verified


  trait FavreBCrypt[PW <: Erasable, SC <: Erasable, T] extends Standard[PW,SC,T]:
    import at.favre.lib.crypto.bcrypt.{BCrypt, LongPasswordStrategy, LongPasswordStrategies}
    import java.security.SecureRandom

    def costFactor : Int

    def bcryptVersion        : BCrypt.Version = BCrypt.Version.VERSION_2A
    def entropy              : SecureRandom   = new SecureRandom()

    def longPasswordStrategy( bv : BCrypt.Version ) : LongPasswordStrategy = LongPasswordStrategies.strict( bv )

    lazy val hasher   : BCrypt.Hasher   = BCrypt.`with`( bcryptVersion, entropy, longPasswordStrategy( bcryptVersion ) )
    lazy val verifier : BCrypt.Verifyer = BCrypt.verifyer( bcryptVersion, longPasswordStrategy( bcryptVersion ) )

end PasswordManager

trait PasswordManager[PW <: Erasable, T]:
  def set( username : String, password : PW, identity : T ) : Unit
  def authenticate( username : String, password : PW )      : Option[T]
end PasswordManager
