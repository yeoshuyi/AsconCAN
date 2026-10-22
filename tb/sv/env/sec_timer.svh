// Timer: per-frame cycle counts, min / avg / max by category, and a CSV with
// one row per frame for plotting latency against length.
//
//   start    first offer of s_axis_tvalid -> first s_axis handshake
//   latency  first s_axis handshake       -> tag_valid
//   tail     data byte with tlast         -> tag_valid   (time to ICV after the frame)
//   post     last s_axis handshake        -> tag_valid   (RX: after the received tag)
//   cyc/B    latency / input bytes
//   key      first key byte               -> have_key

class sec_timer;
    typedef struct {
        longint n;
        longint sum;
        longint mn;
        longint mx;
    } stat_t;

    stat_t      st [string];
    string      cats [$];
    int         csv_fd = 0;
    real        clk_mhz = 100.0;

    function void open_csv(string path);
        if (path == "") return;
        csv_fd = $fopen(path, "w");
        if (csv_fd == 0) begin
            $display("TIMER: cannot open %s, no CSV", path);
            return;
        end
        $fdisplay(csv_fd, "%s", {"id,suite,alg,mode,dir,neg,pass,ad_len,data_len,in_bytes,",
                                 "out_bytes,start,latency,tail,post,s_stall,m_stall,src"});
    endfunction

    function void close_csv();
        if (csv_fd != 0) $fclose(csv_fd);
        csv_fd = 0;
    endfunction

    function void add(string cat, string metric, longint v);
        string k = {cat, "|", metric};
        if (!st.exists(k)) st[k] = '{0, 0, v, v};
        st[k].n++;
        st[k].sum += v;
        if (v < st[k].mn) st[k].mn = v;
        if (v > st[k].mx) st[k].mx = v;
    endfunction

    function void key_load(int alg, longint cycles);
        string c = {alg_name(alg), " key setup"};
        if (!st.exists({c, "|key"})) cats.push_back(c);
        add(c, "key", cycles);
    endfunction

    function void record(sec_frame f, sec_obs o, bit pass);
        string  c = f.kind();
        longint start, latency, tail, post;

        if (o.timeout || !o.got_tag || (o.t_first < 0)) return;
        start   = o.t_first - o.t_offer;
        latency = o.t_tag - o.t_first;
        tail    = (o.t_last_data >= 0) ? o.t_tag - o.t_last_data : -1;
        post    = o.t_tag - o.t_last_in;

        if (!st.exists({c, "|latency"})) cats.push_back(c);
        add(c, "start", start);
        add(c, "latency", latency);
        if (tail >= 0) add(c, "tail", tail);
        add(c, "post", post);
        // cycles per input byte, x100 to keep it integral
        add(c, "cpb", (latency * 100) / ((f.in_bytes() > 0) ? f.in_bytes() : 1));
        add(c, "s_stall", o.s_stall);
        add(c, "m_stall", o.m_stall);

        if (csv_fd != 0) begin
            $fdisplay(csv_fd, "%0d,%s,%s,%s,%s,%s,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,\"%s\"",
                      f.id, f.suite, alg_name(f.alg), f.mode ? "AEAD" : "MAC", f.dir ? "RX" : "TX",
                      f.neg.name(), pass, f.ad.size(), f.data.size(), f.in_bytes(), o.out.size(),
                      start, latency, tail, post, o.s_stall, o.m_stall, f.src);
        end
    endfunction

    function void line(string c, string metric, string label, bit fixed2 = 1'b0);
        string k = {c, "|", metric};
        if (!st.exists(k)) return;
        if (fixed2)
            $display("  %s min %9.2f  avg %9.2f  max %9.2f", pad(label, 9), st[k].mn / 100.0,
                     real'(st[k].sum) / st[k].n / 100.0, st[k].mx / 100.0);
        else
            $display("  %s min %9d  avg %9.1f  max %9d   (avg %.2f us @ %0.0f MHz)", pad(label, 9),
                     st[k].mn, real'(st[k].sum) / st[k].n, st[k].mx,
                     real'(st[k].sum) / st[k].n / clk_mhz, clk_mhz);
    endfunction

    function void report();
        $display("");
        $display("====================== TIMER =======================");
        $display("cycles; frames under backpressure / input gaps included");
        foreach (cats[i]) begin
            string c = cats[i];
            string k = st.exists({c, "|latency"}) ? {c, "|latency"} : {c, "|key"};
            $display("%s  (%0d frames)", c, st[k].n);
            line(c, "key", "key");
            line(c, "start", "start");
            line(c, "latency", "latency");
            line(c, "tail", "tail");
            line(c, "post", "post");
            line(c, "cpb", "cyc/B", 1'b1);
            line(c, "s_stall", "s_stall");
            line(c, "m_stall", "m_stall");
        end
        $display("====================================================");
    endfunction
endclass
