/**********************************************************************************
 * $URL: https://source.etudes.org/svn/apps/resetpw/trunk/resetpw-webapp/webapp/src/java/org/etudes/resetpw/cdp/ResetPwCdpHandler.java $
 * $Id: ResetPwCdpHandler.java 7487 2014-02-22 00:26:58Z ggolden $
 ***********************************************************************************
 *
 * Copyright (c) 2013, 2014 Etudes, Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 **********************************************************************************/

package org.etudes.resetpw.cdp;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.etudes.cdp.api.CdpHandler;
import org.etudes.cdp.api.CdpStatus;
import org.sakaiproject.authz.api.SecurityAdvisor;
import org.sakaiproject.authz.api.SecurityService;
import org.sakaiproject.component.api.ServerConfigurationService;
import org.sakaiproject.component.cover.ComponentManager;
import org.sakaiproject.email.api.EmailService;
import org.sakaiproject.tool.api.SessionManager;
import org.sakaiproject.user.api.User;
import org.sakaiproject.user.api.UserAlreadyDefinedException;
import org.sakaiproject.user.api.UserDirectoryService;
import org.sakaiproject.user.api.UserEdit;
import org.sakaiproject.user.api.UserLockedException;
import org.sakaiproject.user.api.UserNotDefinedException;
import org.sakaiproject.user.api.UserPermissionException;

/**
 */
public class ResetPwCdpHandler implements CdpHandler
{
	/** Our log (commons). */
	private static Log M_log = LogFactory.getLog(ResetPwCdpHandler.class);

	public String getPrefix()
	{
		return "resetpw";
	}

	public Map<String, Object> handle(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String requestPath,
			String path, String authenticatedUserId) throws ServletException, IOException
	{
		if (requestPath.equals("resetPassword"))
		{
			return dispatchResetPassword(req, res, parameters, path);
		}

		return null;
	}

	@SuppressWarnings("rawtypes")
	protected Map<String, Object> dispatchResetPassword(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path)
			throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// get the email parameter
		String email = (String) parameters.get("email");
		if (email == null)
		{
			M_log.warn("dispatchResetPassword - no email parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// build up a map to return - the main map has a single "account" object
		Map<String, String> resultsMap = new HashMap<String, String>();
		rv.put("results", resultsMap);

		// find the users with this email
		Collection found = userDirectoryService().findUsersByEmail(email);
		if (found.isEmpty())
		{
			resultsMap.put("found", "0");
			return rv;

		}
		else if (found.size() > 1)
		{
			resultsMap.put("found", "2");
			return rv;
		}

		else
		{
			User u = (User) found.iterator().next();

			// generate a password
			Random generator = new Random(System.currentTimeMillis());
			Integer num = new Integer(generator.nextInt(Integer.MAX_VALUE));
			if (num.intValue() < 0) num = new Integer(num.intValue() * -1);
			String pw = num.toString();

			// switch to the resetpw user
			String current = sessionManager().getCurrentSessionUserId();
			sessionManager().getCurrentSession().setUserId("resetpw");

			// work under an advisor to permit the edit
			try
			{
				securityService().pushAdvisor(new SecurityAdvisor()
				{
					public SecurityAdvice isAllowed(String userId, String function, String reference)
					{
						return SecurityAdvice.ALLOWED;
					}
				});

				// update the password
				UserEdit edit = userDirectoryService().editUser(u.getId());
				edit.setPassword(pw);
				userDirectoryService().commitEdit(edit);

				// send the email
				notifyPasswordChange(u, pw);
			}
			catch (UserNotDefinedException e)
			{
				rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
				return rv;
			}
			catch (UserPermissionException e)
			{
				rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
				return rv;
			}
			catch (UserLockedException e)
			{
				rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
				return rv;
			}
			catch (UserAlreadyDefinedException e)
			{
				rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
				return rv;
			}
			finally
			{
				securityService().popAdvisor();

				// switch back
				sessionManager().getCurrentSession().setUserId(current);
			}
		}

		resultsMap.put("found", "1");
		resultsMap.put("email", email);

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	/**
	 * Notify the member on being added to a site, possibly a new user.
	 * 
	 * @param user
	 * @param newUserPassword
	 */
	protected void notifyPasswordChange(User user, String newUserPassword)
	{		
		String from = "\"" + serverConfigurationService().getString("ui.service", "Sakai") + "\"<no-reply@"
				+ serverConfigurationService().getServerName() + ">";
		String productionSiteName = serverConfigurationService().getString("ui.service", "");

		String to = user.getEmail();
		String headerTo = user.getEmail();
		String replyTo = user.getEmail();
		String subject = productionSiteName + " Account Information";

		if (from != null && user.getEmail() != null)
		{
			StringBuffer buf = new StringBuffer();
			buf.setLength(0);

			buf.append("Dear " + user.getDisplayName() + ":\n\n");
			buf.append("As you requested, your password has been reset. \n\n");
			buf.append("Your Etudes user id is: " + user.getEid() + "\n\n");
			buf.append("Your temporary password is: " + newUserPassword + "\n\n");
			buf.append("Upon logging on, you will be asked to establish a new, \"strong\" password.\n\n");
			buf.append("Once you change your password, you will be able to access your class(es).\n\n");
			buf.append("---------------------\n\nThis is an automatically generated email from Etudes. Do not reply to it!\n\n");

			String content = buf.toString();
			emailService().send(from, to, subject, content, headerTo, replyTo, null);
		}
	}

	/**
	 * @return The AuthzGroupService, via the component manager.
	 */
	private EmailService emailService()
	{
		return (EmailService) ComponentManager.get(EmailService.class);
	}

	/**
	 * @return The SecurityService, via the component manager.
	 */
	private SecurityService securityService()
	{
		return (SecurityService) ComponentManager.get(SecurityService.class);
	}

	/**
	 * @return The ServerConfigurationService, via the component manager.
	 */
	private ServerConfigurationService serverConfigurationService()
	{
		return (ServerConfigurationService) ComponentManager.get(ServerConfigurationService.class);
	}

	/**
	 * @return The SessionManager, via the component manager.
	 */
	private SessionManager sessionManager()
	{
		return (SessionManager) ComponentManager.get(SessionManager.class);
	}

	/**
	 * @return The UserDirectoryService, via the component manager.
	 */
	private UserDirectoryService userDirectoryService()
	{
		return (UserDirectoryService) ComponentManager.get(UserDirectoryService.class);
	}

}
