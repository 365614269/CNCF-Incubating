/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.themeverifier;

import org.apache.maven.plugin.MojoExecutionException;
import org.owasp.html.PolicyFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.MissingResourceException;
import java.util.Objects;
import java.util.PropertyResourceBundle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VerifyMessageProperties {

    private final File file;
    private List<String> messages;

    public VerifyMessageProperties(File file) {
        this.file = file;
    }

    public List<String> verify() throws MojoExecutionException {
        messages = new ArrayList<>();
        try {
            String contents = Files.readString(file.toPath());
            verifyNoDuplicateKeys(contents);
            verifySafeHtml();
            verifyProblematicBlanks();
        } catch (IOException e) {
            throw new MojoExecutionException("Can not read file " + file, e);
        }
        return messages;
    }

    PolicyFactory POLICY_SOME_HTML = new org.owasp.html.HtmlPolicyBuilder()
            .allowElements(
                    "br", "p", "strong", "b"
            ).toFactory();

    PolicyFactory POLICY_NO_HTML = new org.owasp.html.HtmlPolicyBuilder().toFactory();

    private void verifySafeHtml() {
        PropertyResourceBundle bundle;
        try (FileInputStream fis = new FileInputStream(file)) {
            bundle = new PropertyResourceBundle(fis);
        } catch (IOException e) {
            throw new RuntimeException("unable to read file " + file, e);
        }

        PropertyResourceBundle bundleEnglish;
        String englishFile = file.getAbsolutePath().replaceAll("resources-community", "resources")
                .replaceAll("_[a-zA-Z-_]*\\.properties", "_en.properties");
        try (FileInputStream fis = new FileInputStream(englishFile)) {
            bundleEnglish = new PropertyResourceBundle(fis);
        } catch (IOException e) {
            throw new RuntimeException("unable to read file " + englishFile, e);
        }

        bundle.getKeys().asIterator().forEachRemaining(key -> {
            String value = bundle.getString(key);
            value = normalizeValue(key, value);
            String englishValue = getEnglishValue(key, bundleEnglish);
            englishValue = normalizeValue(key, englishValue);

            value = santizeAnchors(key, value, englishValue);

            // Only if the English source string contains HTML we also allow HTML in the translation
            PolicyFactory policy = containsHtml(englishValue) ? POLICY_SOME_HTML : POLICY_NO_HTML;
            String sanitized = policy.sanitize(value);

            // Sanitizer will escape HTML entities for quotes and also for numberic tags like '<1>'
            sanitized = org.apache.commons.text.StringEscapeUtils.unescapeHtml4(sanitized);
            // Sanitizer will add them when there are double curly braces
            sanitized = sanitized.replace("<!-- -->", "");

            if (!Objects.equals(sanitized, value)) {

                // Strip identical characters from the beginning and the end to show where the difference is
                int start = 0;
                while (start < sanitized.length() && start < value.length() && value.charAt(start) == sanitized.charAt(start)) {
                    start++;
                }
                int end = 0;
                while (end < sanitized.length() && end < value.length() && value.charAt(value.length() - end - 1) == sanitized.charAt(sanitized.length() - end - 1)) {
                    end++;
                }

                messages.add("Illegal HTML in key " + key + " for file " + file + ": '" + value.substring(start, value.length() - end) + "' vs. '" + sanitized.substring(start, sanitized.length() - end) + "'");
            }

        });
    }

    /**
     * Double blanks and blanks at the beginning of end of the string are difficult to translation in the translation tools and
     * are easily missed. If a blank before or after the string is needed in the UI, add it in the HTML template.
     */
    private void verifyProblematicBlanks() {
        if (!file.getName().endsWith("_en.properties")) {
            // Only check EN original files, as the other files are checked by the translation tools
            return;
        }
        PropertyResourceBundle bundle;
        try (FileInputStream fis = new FileInputStream(file)) {
            bundle = new PropertyResourceBundle(fis);
        } catch (IOException e) {
            throw new RuntimeException("unable to read file " + file, e);
        }

        bundle.getKeys().asIterator().forEachRemaining(key -> {
            String value = bundle.getString(key);

            if (value.contains("  ")) {
                messages.add("Duplicate blanks in " + key + " for file " + file + ": '" + value);
            }

            if (value.startsWith(" ")) {
                messages.add(key + " starts with a blank in file " + file + ": '" + value);
            }

            if (value.endsWith(" ")) {
                messages.add(key + " ends with a blank in file " + file + ": '" + value);
            }
        });
    }

    private String normalizeValue(String key, String value) {
        if (key.equals("templateHelp")) {
            // Allow "CLAIM.<NAME>" here
            value = value.replaceAll("CLAIM\\.<[A-Z]*>", "");
        } else if (key.equals("optimizeLookupHelp")) {
            // Allow "<Extensions>" here
            value = value.replaceAll("<Extensions>", "");
        } else if (key.startsWith("linkExpirationFormatter.timePeriodUnit") || key.equals("error-invalid-multivalued-size")) {
            // The problem is the "<" that appears in the choice
            value = value.replaceAll("\\{[0-9]+,choice,[^}]*}", "...");
        }

        // Unescape HTML entities, as we later also unescape HTML entities in the sanitized value
        value = org.apache.commons.text.StringEscapeUtils.unescapeHtml4(value);

        return value;
    }

    Pattern HTML_TAGS = Pattern.compile("<[a-z]+[^>]*>");

    private boolean containsHtml(String englishValue) {
        return HTML_TAGS.matcher(englishValue).find();
    }

    private static final Pattern ANCHOR_PATTERN = Pattern.compile("</?a[^>]*>");

    /**
     * Allow only those anchor tags from the source key to also appear in the target key.
     */
    private String santizeAnchors(String key, String value, String englishValue) {
        Matcher matcher = ANCHOR_PATTERN.matcher(value);
        Matcher englishMatcher = ANCHOR_PATTERN.matcher(englishValue);
        while (matcher.find()) {
            if (englishMatcher.find() && Objects.equals(matcher.group(), englishMatcher.group())) {
                value = value.replaceFirst(Pattern.quote(englishMatcher.group()), "");
            } else {
                messages.add("Didn't find anchor tag " + matcher.group() + " in original string");
                break;
            }
        }
        return value;
    }

    private static String getEnglishValue(String key, PropertyResourceBundle bundleEnglish) {
        String englishValue;
        try {
            englishValue = bundleEnglish.getString(key);
        } catch (MissingResourceException ex) {
            englishValue = "";
        }
        return englishValue;
    }

    private void verifyNoDuplicateKeys(String contents) throws IOException {
        BufferedReader bufferedReader = new BufferedReader(new StringReader(contents));
        String line;
        HashSet<String> seenKeys = new HashSet<>();
        HashSet<String> duplicateKeys = new HashSet<>();
        while ((line = bufferedReader.readLine()) != null) {
            if (line.startsWith("#") || line.isEmpty()) {
                continue;
            }
            int split = line.indexOf("=");
            if (split != -1) {
                String key = line.substring(0, split).trim();
                if (seenKeys.contains(key)) {
                    duplicateKeys.add(key);
                } else {
                    seenKeys.add(key);
                }
            }
        }
        if (!duplicateKeys.isEmpty()) {
            messages.add("Duplicate keys in file '" + file.getAbsolutePath() + "': " + duplicateKeys);
        }
    }
}
