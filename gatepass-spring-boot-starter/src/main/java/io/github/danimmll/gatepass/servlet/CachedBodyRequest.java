package io.github.danimmll.gatepass.servlet;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import org.jspecify.annotations.Nullable;

import io.github.danimmll.gatepass.internal.ByteArrayServletInputStream;

/**
 * A request whose body has already been read and checked, handed on from memory.
 *
 * <p>Once the body has been read, the container no longer parses form parameters from it, so for an
 * {@code application/x-www-form-urlencoded} POST this wrapper parses them itself, after those of the query string, as
 * the container would have.
 */
final class CachedBodyRequest extends HttpServletRequestWrapper {

    private final byte[] body;

    private @Nullable Map<String, String[]> parameters;

    CachedBodyRequest(HttpServletRequest request, byte[] body) {
        super(request);
        this.body = body;
    }

    @Override
    public ServletInputStream getInputStream() {
        return new ByteArrayServletInputStream(this.body);
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(new ByteArrayInputStream(this.body), charset()));
    }

    @Override
    public @Nullable String getParameter(String name) {
        String[] values = parameters().get(name);
        return (values != null && values.length > 0) ? values[0] : null;
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        return parameters();
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return Collections.enumeration(parameters().keySet());
    }

    @Override
    public String @Nullable [] getParameterValues(String name) {
        String[] values = parameters().get(name);
        return (values != null) ? values.clone() : null;
    }

    private Map<String, String[]> parameters() {
        Map<String, String[]> parameters = this.parameters;
        if (parameters == null) {
            Map<String, List<String>> merged = new LinkedHashMap<>();
            super.getParameterMap().forEach((name, values) -> merged.computeIfAbsent(name, key -> new ArrayList<>())
                    .addAll(Arrays.asList(values)));
            if (isFormPost()) {
                parseForm(merged);
            }
            Map<String, String[]> result = new LinkedHashMap<>();
            merged.forEach((name, values) -> result.put(name, values.toArray(new String[0])));
            parameters = Collections.unmodifiableMap(result);
            this.parameters = parameters;
        }
        return parameters;
    }

    private boolean isFormPost() {
        String contentType = getContentType();
        return "POST".equalsIgnoreCase(getMethod()) && contentType != null
                && contentType.stripLeading().regionMatches(true, 0, "application/x-www-form-urlencoded", 0, 33);
    }

    private void parseForm(Map<String, List<String>> into) {
        Charset charset = charset();
        // ISO-8859-1 maps bytes to chars one to one, so the percent-escapes survive until they are decoded.
        for (String pair : new String(this.body, StandardCharsets.ISO_8859_1).split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int equals = pair.indexOf('=');
            String name = decode((equals < 0) ? pair : pair.substring(0, equals), charset);
            String value = (equals < 0) ? "" : decode(pair.substring(equals + 1), charset);
            if (!name.isEmpty()) {
                into.computeIfAbsent(name, key -> new ArrayList<>()).add(value);
            }
        }
    }

    private static String decode(String value, Charset charset) {
        try {
            return URLDecoder.decode(value, charset);
        }
        catch (IllegalArgumentException ex) {
            return value;
        }
    }

    private Charset charset() {
        String encoding = getCharacterEncoding();
        if (encoding != null) {
            try {
                return Charset.forName(encoding);
            }
            catch (IllegalArgumentException ex) {
                // Fall back to the servlet default below.
            }
        }
        return StandardCharsets.ISO_8859_1;
    }

}
