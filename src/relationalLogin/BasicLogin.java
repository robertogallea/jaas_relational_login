// $Id: BasicLogin.java,v 1.5 2003/02/17 20:13:23 andy Exp $
package relationalLogin;

import javax.security.auth.spi.LoginModule;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import java.util.Map;

/**
 * Superclass for all the com.tagish.auth.* authorisation modules. Provides
 * utility methods for reading the module's configuration options and a
 * default implementation of initialize() that fetches the value of a boolean
 * option called 'debug'.
 *
 * @author Andy Armstrong, <A HREF="mailto:andy@tagish.com">andy@tagish.com</A>
 * @version 1.0.3
 */
public abstract class BasicLogin implements LoginModule
{
	// initial state
	protected Subject			subject;
	protected CallbackHandler	callbackHandler;
	protected Map				sharedState;
	protected Map				options;

	// configurable option
	protected boolean			debug			= false;

	public BasicLogin()
	{
	}

	/**
	 * Module initialization.
	 */
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options)
	{
		// Stash our copy of supplied arguments
		this.subject			= subject;
		this.callbackHandler	= callbackHandler;
		this.sharedState		= sharedState;
		this.options            = options;

		// initialize any configured options
		debug = getOption("debug", debug);
	}

	/**
	 * Get a boolean option from the module's options.
	 *
	 * @param name Name of the option
	 * @param dflt Default value for the option
	 * @return The boolean value of the options object.
	 */
	protected boolean getOption(String name, boolean dflt)
	{
		String opt = ((String) options.get(name));

		if (opt == null) return dflt;

		opt = opt.trim();
		if (opt.equalsIgnoreCase("true") || opt.equalsIgnoreCase("yes") || opt.equals("1"))
			return true;
		else if (opt.equalsIgnoreCase("false") || opt.equalsIgnoreCase("no") || opt.equals("0"))
			return false;
		else
			return dflt;
	}

	/**
	 * Get a numeric option from the module's options.
	 *
	 * @param name Name of the option
	 * @param dflt Default value for the option
	 * @return The boolean value of the options object.
	 */
	protected int getOption(String name, int dflt)
	{
		String opt = ((String) options.get(name));
		if (opt == null) return dflt;
		try { dflt = Integer.parseInt(opt); } catch (Exception e) { }
		return dflt;
	}

	/**
	 * Get a String option from the module's options.
	 *
	 * @param name Name of the option
	 * @param dflt Default value for the option
	 * @return The String value of the options object.
	 */
	protected String getOption(String name, String dflt)
	{
		String opt = (String) options.get(name);
		return opt == null ? dflt : opt;
	}
}
