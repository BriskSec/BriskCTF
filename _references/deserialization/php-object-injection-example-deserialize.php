class DangerousClass {

    function __construct() {
        $this->cmd = "id";
    }
    
    function __destruct() {
        echo passthru($this->cmd);
    }

}
class NormalClass {

    function __construct() {
        $this->name = "bob";
    }
    
    function __destruct() {
        echo $this->name;
    }

}
$serial = file_get_contents('/tmp/serial');
unserialize($serial);
