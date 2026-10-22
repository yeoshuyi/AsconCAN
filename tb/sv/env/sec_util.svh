// Small string and byte-queue helpers

function automatic bit is_space(byte c);
    // Numeric codes: xsim does not take "\r" as a carriage return, and the
    // CAVP files have CRLF line ends
    return (c == 8'h20) || (c == 8'h09) || (c == 8'h0A) || (c == 8'h0D);
endfunction

function automatic string str_trim(string s);
    int a = 0;
    int b = s.len() - 1;
    while ((a <= b) && is_space(s.getc(a))) a++;
    while ((b >= a) && is_space(s.getc(b))) b--;
    return (a > b) ? "" : s.substr(a, b);
endfunction

function automatic string str_basename(string path);
    for (int i = path.len() - 1; i >= 0; i--) begin
        if (path.getc(i) == "/") return path.substr(i + 1, path.len() - 1);
    end
    return path;
endfunction

function automatic int hex_nibble(byte c);
    if ((c >= "0") && (c <= "9")) return c - "0";
    if ((c >= "a") && (c <= "f")) return c - "a" + 10;
    if ((c >= "A") && (c <= "F")) return c - "A" + 10;
    return -1;
endfunction

// Returns 0 on malformed hex
function automatic bit hex2bq(string s, output bq_t q);
    q = {};
    if ((s.len() % 2) != 0) return 1'b0;
    for (int i = 0; i < s.len(); i += 2) begin
        int hi = hex_nibble(s.getc(i));
        int lo = hex_nibble(s.getc(i + 1));
        if ((hi < 0) || (lo < 0)) return 1'b0;
        q.push_back(byte'((hi << 4) | lo));
    end
    return 1'b1;
endfunction

function automatic string bq2hex(bq_t q, int max_bytes = 48);
    string s = "";
    int n = (q.size() < max_bytes) ? q.size() : max_bytes;
    for (int i = 0; i < n; i++) s = {s, $sformatf("%02x", q[i])};
    if (q.size() > max_bytes) s = {s, $sformatf("..(+%0d)", q.size() - max_bytes)};
    return s;
endfunction

function automatic bq_t bq_slice(bq_t q, int from, int n);
    bq_t r;
    for (int i = from; (i < from + n) && (i < q.size()); i++) r.push_back(q[i]);
    return r;
endfunction

function automatic string alg_name(int alg);
    return (alg == ALG_AES) ? "AES" : "Ascon";
endfunction

function automatic string mode_name(int alg, bit mode);
    if (alg == ALG_AES) return mode ? "AES-128-GCM" : "AES-128-CMAC";
    return mode ? "Ascon-AEAD128" : "Ascon-MAC";
endfunction

// Left-justify to w characters ($display's %-Ns is not honoured by xsim)
function automatic string pad(string s, int w);
    while (s.len() < w) s = {s, " "};
    return s;
endfunction

// Flip one random bit of one random byte. The index is picked once: in
// "q[$urandom_range(n)] ^= m" it is evaluated twice, on the read and the write.
function automatic void flip_bit(ref bq_t q);
    int i;
    if (q.size() == 0) return;
    i = $urandom_range(q.size() - 1);
    q[i] = q[i] ^ 8'(1 << $urandom_range(7));
endfunction
