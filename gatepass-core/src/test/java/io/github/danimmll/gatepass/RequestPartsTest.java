package io.github.danimmll.gatepass;

import java.net.URI;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class RequestPartsTest {

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "/                                   | /             | ''",
            "/a/b                                | /a/b          | ''",
            "/a/b?x=1                            | /a/b          | x=1",
            "/a/b?                               | /a/b          | ''",
            "/a/b#section                        | /a/b          | ''",
            "/a/b?x=1#section                    | /a/b          | x=1",
            "/a%20b/c%2Fd?q=a%20b&r=%2B+         | /a%20b/c%2Fd  | q=a%20b&r=%2B+",
            "?x=1                                | /             | x=1",
            "http://host                         | /             | ''",
            "http://host/                        | /             | ''",
            "http://host?x=1                     | /             | x=1",
            "http://host:8080/a/b?x=1#f          | /a/b          | x=1",
            "https://user@host/a                 | /a            | ''",
            "lb://orders/api/orders/5            | /api/orders/5 | ''",
            "/redirect?to=http://elsewhere/x?y=1 | /redirect     | to=http://elsewhere/x?y=1",
    })
    void takesThePathAndTheQueryStringAsTheyGoOnTheWire(String url, String path, String query) {
        RequestParts parts = RequestParts.fromUrl("GET", url);

        assertThat(parts.rawPath()).isEqualTo(path);
        assertThat(parts.rawQuery()).isEqualTo(query);
    }

    @ParameterizedTest
    @NullAndEmptySource
    void nothingIsTheRootWithoutAQueryString(String url) {
        assertThat(RequestParts.fromUrl("GET", url)).isEqualTo(new RequestParts("GET", "/", ""));
        assertThat(RequestParts.of("GET", null, null)).isEqualTo(new RequestParts("GET", "/", ""));
    }

    @Test
    void nonAsciiCharactersArePercentEncodedAsHttpClientsSendThem() throws Exception {
        URI uri = new URI("http", "orders", "/café", "name=ñandú", null);

        assertThat(RequestParts.fromUri("GET", uri)).isEqualTo(new RequestParts("GET", "/caf%C3%A9", "name=%C3%B1and%C3%BA"));
        assertThat(RequestParts.fromUrl("GET", "http://orders/café?name=ñandú")).isEqualTo(RequestParts.fromUri("GET", uri));
    }

    @Test
    void methodIsUpperCase() {
        assertThat(RequestParts.of("patch", "/a", null).method()).isEqualTo("PATCH");
    }

    @Test
    void lineBreaksAreRefusedBecauseTheyWouldMakeTheSignedTextAmbiguous() {
        assertThatIllegalArgumentException().isThrownBy(() -> RequestParts.of("GET", "/a\nb", null));
        assertThatIllegalArgumentException().isThrownBy(() -> RequestParts.of("GET", "/a", "x=1\r\ny=2"));
    }

}
