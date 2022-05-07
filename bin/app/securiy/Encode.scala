package security

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

import java.io.IOException;
import java.security.KeyPair;
import javax.xml.bind.DatatypeConverter;

class Encode {

  val argon2 = Argon2Factory.create();

  def hashpw(pass: String): String = {

    val passwordChars = pass.toCharArray();

    val stored = argon2.hash(22, 65536, 1, passwordChars);

    argon2.wipeArray(passwordChars);

    try {

      return stored

    } catch {
      case e: Exception => {

      return "";
      }
    }
  }

  def verify(pass :String, hash: String): Boolean = {
      try{

        return argon2.verify(hash, pass.toCharArray());

    } catch {
      case e: Exception => {
        return false;
      }
    }
  }
}
