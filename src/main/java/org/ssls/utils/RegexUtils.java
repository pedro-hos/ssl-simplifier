/**
 * 
 */
package org.ssls.utils;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author pedro-hos@outlook.com
 *
 */
public class RegexUtils {

	/**
	 * 
	 * @param content
	 * @param regex
	 * @param group
	 * @return
	 */
	public static Set<String> extractListByRegexAndGroup(final String content, final String regex, final int group) {

		Set<String> allMatches = new HashSet<String>();

		Matcher m = getMatcher(regex, content);

		while (m.find()) {
			allMatches.add(m.group(group));
		}

		return allMatches;
	}

	/**
	 * 
	 * @param matcher
	 * @param group
	 * @return
	 */
	public static String getByGroup(final Matcher matcher, final int group) {
		return matcher.find() ? matcher.group(group) : "";
	}

	/**
	 * 
	 * @param regex
	 * @param value
	 * @return
	 */
	public static Matcher getMatcher(final String regex, final String value) {
		final Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
		return pattern.matcher(value);
	}

}
