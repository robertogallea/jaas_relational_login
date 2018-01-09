// $Id: SimpleLogin.java,v 1.5 2003/02/17 20:13:23 andy Exp $
package relationalLogin;

import java.util.*;
import java.security.Principal;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;

/**
 * Base class for a variety of simple login modules that simply authenticate
 * a user against some database of user credentials.
 *
 * @author Andy Armstrong, <A HREF="mailto:andy@tagish.com">andy@tagish.com</A>
 * @version 1.0.3
 */
public abstract class SimpleLogin extends BasicLogin
{
	protected Vector			principals      = null;
	protected Vector            pending         = null;

	// the authentication status
	protected boolean			commitSucceeded = false;

	/**
	 * Validate a user's credentials and either throw a LoginException (if
	 * validation fails) or return a Vector of Principals if validation
	 * succeeds.
	 *
	 * @param username The username
	 * @param password The password
	 * @return a Vector of Principals that apply for this user.
	 * @throws LoginException if the login fails.
	 */
	protected abstract Vector validateUser(String username, char password[]) throws LoginException;

	/**
	 * Authenticate the user.
	 *
	 * @return true in all cases since this <code>LoginModule</code> should not be ignored.
	 * @exception FailedLoginException if the authentication fails. <p>
	 * @exception LoginException if this <code>LoginModule</code>
	 * 		is unable to perform the authentication.
	 */
	public boolean login() throws LoginException
	{
		// username and password
		String	username;
		char	password[] = null;

		try {
			// prompt for a username and password
			if (callbackHandler == null)
				throw new LoginException("Error: no CallbackHandler available to garner authentication information from the user");

			Callback[] callbacks = new Callback[2];
			callbacks[0] = new NameCallback("Username: ");
			callbacks[1] = new PasswordCallback("Password: ", false);

			try {
				callbackHandler.handle(callbacks);

				// Get username...
				username = ((NameCallback) callbacks[0]).getName();

				// ...password...
				password = ((PasswordCallback) callbacks[1]).getPassword();
				((PasswordCallback)callbacks[1]).clearPassword();
			} catch (java.io.IOException ioe) {
				throw new LoginException(ioe.toString());
			} catch (UnsupportedCallbackException uce) {
				throw new LoginException("Error: " + uce.getCallback().toString() +
						" not available to garner authentication information from the user");
			}

			// Attempt to logon using the supplied credentials
			pending = null;
			pending = validateUser(username, password);     // may throw
		} finally {
			Utils.smudge(password);
		}

		return true;
	}

	/**
	 * Place the specified <CODE>Principle</CODE> in the subject and also record it in our
	 * principles <CODE>Vector</CODE> so we can remove them all later.
	 *
	 * @param s The <CODE>Set</CODE> to add the Principle to
	 * @param p Principle to add
	 */
	protected void putPrincipal(Set s, Principal p)
	{
		s.add(p);
		principals.add(p);
	}

	/**
	 * <p> This method is called if the LoginContext's overall authentication
	 * succeeded (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL
	 * LoginModules succeeded).
	 *
	 * <p>If this LoginModule's own authentication attempt
	 * succeeded (checked by retrieving the private state saved by the
	 * <code>login</code> method), then this method associates a
	 * number of <code>NTPrincipal</code>s
	 * with the <code>Subject</code> located in the
	 * <code>LoginModule</code>.  If this LoginModule's own
	 * authentication attempted failed, then this method removes
	 * any state that was originally saved.
	 *
	 * <p>
	 *
	 * @return true if this LoginModule's own login and commit
	 * 		attempts succeeded, or false otherwise.
	 * @exception LoginException if the commit fails.
	 */
	public boolean commit() throws LoginException
	{
		if (pending == null) {
			return false;
		}

		principals = new Vector();
		Set s = subject.getPrincipals();

		for (int p = 0; p < pending.size(); p++) {
			putPrincipal(s, (Principal) pending.get(p));
		}

		commitSucceeded = true;
		return true;
	}

	/**
	 * <p> This method is called if the LoginContext's
	 * overall authentication failed.
	 * (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL LoginModules
	 * did not succeed).
	 *
	 * <p> If this LoginModule's own authentication attempt
	 * succeeded (checked by retrieving the private state saved by the
	 * <code>login</code> and <code>commit</code> methods),
	 * then this method cleans up any state that was originally saved.<p>
	 *
	 * @exception LoginException if the abort fails.
	 *
	 * @return false if this LoginModule's own login and/or commit attempts
	 *		failed, and true otherwise.
	 */
	public boolean abort() throws LoginException
	{
		if (pending == null) {
			return false;
		} else if (pending != null && !commitSucceeded) {
			pending = null;
		} else {
			logout();
		}
		return true;
	}

	/**
	 * Logout the user.
	 *
	 * <p> This method removes the <code>Principal</code>s
	 * that were added by the <code>commit</code> method.
	 *
	 * <p>
	 *
	 * @return true in all cases since this <code>LoginModule</code>
	 *          should not be ignored.
	 * @exception LoginException if the logout fails.
	 */
	public boolean logout() throws LoginException
	{
		pending         = null;
		commitSucceeded	= false;
		// Remove all the principals we added
		Set s = subject.getPrincipals();
		int sz = principals.size();
		for (int p = 0; p < sz; p++) {
			s.remove(principals.get(p));
		}
		principals = null;

		return true;
	}
}
