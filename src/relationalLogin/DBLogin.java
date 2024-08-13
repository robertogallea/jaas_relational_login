// $Id: DBLogin.java,v 1.5 2003/02/17 20:13:23 andy Exp $
package relationalLogin;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.sql.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.apache.commons.codec.digest.Crypt;

/**
 * Simple database based authentication module.
 *
 * @author Andy Armstrong, <A HREF="mailto:andy@tagish.com">andy@tagish.com</A>
 * @version 1.0.3
 */
public class DBLogin extends SimpleLogin
{
	protected String                dbDriver;
	protected String                dbURL;
	protected String                dbUser;
	protected String                dbPassword;
	protected String                userTable;
	protected String                userColumn;
	protected String                passColumn;
	protected String                saltColumn;
	protected String                lastLoginColumn;
	protected String                where;

	private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

	protected synchronized Vector validateUser(String username, char password[]) throws LoginException {
		try {
			Class.forName(dbDriver);
	
			try (Connection con = (dbUser != null) ? DriverManager.getConnection(dbURL, dbUser, dbPassword) : DriverManager.getConnection(dbURL);
				 PreparedStatement psu = con.prepareStatement("SELECT " + passColumn + (!saltColumn.equals("") ? ("," + saltColumn) : "") + " FROM " + userTable +
															  " WHERE " + userColumn + "=?" + where)) {
	
				psu.setString(1, username);
				try (ResultSet rsu = psu.executeQuery()) {
					if (!rsu.next()) {
						throw new FailedLoginException(getOption("errorMessage", "Invalid details"));
					}
	
					String upwd = rsu.getString(1);
					String salt = (!saltColumn.equals("") ? rsu.getString(2) : "");
	
					String tpwd = new String();
					String hashingAlg = getOption("hashAlgorithm", null);
	
					if (hashingAlg != null && (!hashingAlg.isEmpty())) {
						if (hashingAlg.toLowerCase().equals("bcrypt")) {
							tpwd = new String(password);
							String upwd2 = "$2a" + upwd.substring(3);
							if (!passwordEncoder.matches(tpwd, upwd2))
								throw new FailedLoginException(getOption("errorMessage", "Invalid details (b)"));
						} else if (hashingAlg.toLowerCase().equals("crypt")) {
							tpwd = new String(password);
							if (!upwd.equals(Crypt.crypt(tpwd.getBytes(), upwd)))
								throw new FailedLoginException(getOption("errorMessage", "Invalid details"));
						} else {
							try {
								tpwd = this.hash(new String(password) + salt, hashingAlg);
							} catch (NoSuchAlgorithmException ex) {
								Logger.getLogger(DBLogin.class.getName()).log(Level.SEVERE, null, ex);
							}
							if (!upwd.toLowerCase().equals(tpwd.toLowerCase()))
								throw new FailedLoginException(getOption("errorMessage", "Invalid details"));
						}
					} else {
						tpwd = new String(password);
						if (!upwd.equals(tpwd))
							throw new FailedLoginException(getOption("errorMessage", "Invalid details"));
					}
	
					if (!lastLoginColumn.equals("")) {
						try (PreparedStatement psuUpdate = con.prepareStatement("UPDATE " + userTable + " SET " + lastLoginColumn + " = CURRENT_TIMESTAMP WHERE " + userColumn + "= ?")) {
							psuUpdate.setString(1, username);
							psuUpdate.executeUpdate();
						} catch (SQLException e) {
							throw new LoginException("Database error: " + e.getMessage());
						}
					}
	
					Vector p = new Vector();
					p.add(new TypedPrincipal(username, TypedPrincipal.USER));
					return p;
				}
			}
		} catch (ClassNotFoundException e) {
			throw new LoginException("Error reading user database (" + e.getMessage() + ")");
		} catch (SQLException e) {
			throw new LoginException("Error reading user database (" + e.getMessage() + ")");
		}
	}

	public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options)
	{
		super.initialize(subject, callbackHandler, sharedState, options);

		dbDriver = getOption("dbDriver", null);
		if (dbDriver == null) throw new Error("No database driver named (dbDriver=?)");
		dbURL = getOption("dbURL", null);
		if (dbURL == null) throw new Error("No database URL specified (dbURL=?)");
		dbUser = getOption("dbUser", null);
		dbPassword = getOption("dbPassword", null);
		if ((dbUser == null && dbPassword != null) || (dbUser != null && dbPassword == null))
		   throw new Error("Either provide dbUser and dbPassword or encode both in dbURL");

		userTable       = getOption("userTable",       "User");
		userColumn      = getOption("userColumn",      "user_name");
		passColumn      = getOption("passColumn",      "user_passwd");
		saltColumn      = getOption("saltColumn",      "");
		lastLoginColumn	= getOption("lastLoginColumn", "");
		where           = getOption("where",           "");

		if (null != where && where.length() > 0)
			where = " AND " + where;
		else
			where = "";
	}
        
        String hash(String input, String hashingAlg) throws NoSuchAlgorithmException {
            MessageDigest mDigest = MessageDigest.getInstance(hashingAlg);
            byte[] result = mDigest.digest(input.getBytes());
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < result.length; i++) {
                sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
            }
         
        return sb.toString();
    }
}
