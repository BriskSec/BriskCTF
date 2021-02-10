class DangerousClass {

    function __construct() {
        $this->cmd = "ls";
    }
    
    function __destruct() {
        echo passthru($this->cmd);
    }

}
$a = new DangerousClass();
$b = serialize($a);
file_put_contents("/tmp/serial", $b);
