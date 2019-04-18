<html>
<head>
    <title>Statistics</title>
    <style>
#errordist {
        float:  left;
        width:  500px;
    }
#statistics {
        float:  right;
        width:  500px;
    }
#fuzzers {
        clear:  both;
    }
#notable_results {
        background-color:   red;
        color:              white;
    }
table {
    padding:            2px;
    border-style:       solid;
    border-color:       #000;
    border-collapse:    collapse;
    width:              100%;
    margin:             10px 10px 10px 10px;
}

td {
    border:             1px solid #000;
    text-align:         left;
    width:              50%;
}

th {
    border:             1px solid #000;
    background-color:   #ccc;
    color:              #000;
    text-align:         left;
}

    </style>
</head>
<body>
<h1>iknowthis Statistics Generated on <?cs var:Page.date ?></h1>
<div id="global">
    <div id="errordist">
        <img src="http://chart.apis.google.com/chart?cht=p&chs=720x300&chl=<?cs each:i = Global.errors ?><?cs var:i.description ?>|<?cs /each ?>&chd=t:<?cs each:i = Global.errors ?><?cs var:i.count ?>,<?cs /each ?>0">
    </div>
    <div id="statistics">
        <table id="globalstats">
            <th colspan="2">Global Statistics</th>
            <tr>
                <td>Total Fuzzers</td>
                <td><?cs var:Global.num_fuzzers ?></td>
            </tr>
            <tr>
                <td>Total Executions</td>
                <td>
                    <?cs var:Global.total_executions ?> (<?cs var:Global.total_successes ?> Success / <?cs var:Global.total_failures ?> Failure)
                </td>
            </tr>
            <?cs each:i = Global.errors ?>
                <tr>
                    <td><?cs var:i.description ?></td>
                    <td><?cs var:i.count ?></td>
                </tr>
            <?cs /each ?>
        </table>
    </div>
    <div id="fuzzers">
        <table>
            <th colspan="2">Fuzzer Statistics</th>
            <tr>
                <td>Slowest Fuzzer</td>
                <td><?cs var:Global.slowest_fuzzer.name ?> (<?cs var:Global.slowest_fuzzer.speed ?> us)</td>
            </tr>
            <tr>
                <td>Fastest Fuzzer</td>
                <td><?cs var:Global.fastest_fuzzer.name ?> (<?cs var:Global.fastest_fuzzer.speed ?> us)</td>
            </tr>
        </table>
    <div>
</div>

<div id="notable_results">
    <table>
        <tr>
            <th>The following system call numbers do not have fuzzers defined.</th>
        </tr>
        <tr><td>
        <?cs each:i = Global.fuzzer_missing ?>
                <?cs var:i.number ?>,
        <?cs /each ?>
        </td></tr>
    </table>
    <table>
        <tr>
            <th>The following system calls have fuzzers defined, but are disabled.</th>
        </tr>
        <tr><td>
        <?cs each:i = Global.fuzzer_disabled ?>
                <a href="#<?cs var:i.name ?>"><?cs var:i.name ?></a>,
        <?cs /each ?>
        </td></tr>
    </table>
    <table>
        <tr>
            <th>The following fuzzers always fail, but are not marked SYS_FAIL.</th>
        </tr>
        <tr><td>
        <?cs each:i = Global.fuzzer_always_fails ?>
                <a href="#<?cs var:i.name ?>"><?cs var:i.name ?></a>,
        <?cs /each ?>
        </td></tr>
    </table>
    <table>
        <tr>
            <th>The following fuzzers always return the same value, but are not marked SYS_BORING.</th>
        </tr>
        <tr><td>
        <?cs each:i = Global.fuzzer_always_same ?>
                <a href="#<?cs var:i.name ?>"><?cs var:i.name ?></a>,
        <?cs /each ?>
        </td></tr>
    </table>
    <table>
        <tr>
            <th>The following fuzzers are marked SYS_BORING, but are returning multiple values.</th>
        </tr>
        <tr><td>
        <?cs each:i = Global.fuzzer_not_boring ?>
                <a href="#<?cs var:i.name ?>"><?cs var:i.name ?></a>,
        <?cs /each ?>
        </td></tr>
    </table>
    <table>
        <tr>
            <th>The following fuzzers are marked SYS_FAIL, but have returned success.</th>
        </tr>
        <tr><td>
        <?cs each:i = Global.fuzzer_not_failing ?>
                <a href="#<?cs var:i.name ?>"><?cs var:i.name ?></a>,
        <?cs /each ?>
        </td></tr>
    </table>
</div>
<div>
    <?cs each:i = Fuzzer ?>
        <table>
            <th colspan="2">
                <a name="<?cs var:i.Name ?>" href="http://www.kernel.org/doc/man-pages/online/pages/man2/<?cs var:i.Name ?>.2.html" target="manual"><?cs var:i.Name ?></a>
            </th>
            <tr>
                <td>Total</td>
                <td><?cs var:i.Total ?></td>
            </tr>
            <tr>
                <td>Failures</td>
                <td><?cs var:i.Failures ?></td>
            </tr>
            <tr>
                <td>Unique Errors</td>
                <td><?cs var:i.NumErrors ?></i>
            </tr>
            <th colspan="2">Error Distribution</th>
            <tr>
                <?cs each:err = i.Errors ?>
                    <tr>
                        <td><?cs var:err.error ?>
                        <td><?cs var:err.count ?>
                    </tr>
                <?cs /each ?>
            </tr>
        </table>
    <?cs /each ?>
</div>
</body>
</html>
