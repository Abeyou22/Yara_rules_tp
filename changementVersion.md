Allez dans le dossier où vous avez télécharger le fichier
```
tar -zxf yara-X.X.X.tar.gz
cd yara-X.X.X
sudo apt-get install automake libtool make gcc pkg-config
./bootstrap.sh
./configure --enable-cuckoo --enable-magic --enable-dotnet
make
sudo make install
```

Vous aurez surement besoin d'installer les librairies suivantes
```
sudo apt-get install libjansson-dev
sudo apt-get install libmagic-dev
```

Effectuez la command `yara -v` pour verifier la version
si vous obtenez le message suivant
```
yara: error while loading shared libraries: libyara.so.10: cannot open shared object file: No such file or directory
```

Chezchez la librairire manquante : `sudo find / -name libyara.so.10`

Si vous obtenez un chemin d'accès du style : `/usr/local/lib/libyara.so.10`, ajoutez la au fichier "/etc/ld.so.conf" grâce à la commande :
```
sudo sh -c 'echo "/usr/local/lib" >> /etc/ld.so.conf'
sudo ldconfig
```


Ensuite refaite `yara -v`, si vous n'avez pas encore la bonne version, recommencez la procédure depuis le début.

Si vous avez un autre problème, n'hésitez pas à contacter quelqu'un de l'équipe du projet YARA et à documenter vos actions.
