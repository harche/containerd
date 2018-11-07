/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package jwe

import (
	"encoding/base64"
	"strings"
)

func b64Dec(str string) string {
	str = strings.Replace(str, " ", "", -1)
	s, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		panic(err)
	}

	return string(s)
}

// Start JWE Keys
var (
	jwePrivKeyPem = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAsl+vKscbGU8TeGLoYJAt+i9zudJtBisoeB4C35EqiRgPXslN
6Qu6AP5FTcR4mBYVzM1txmBELMtZHrZFfRTMRCr3y4JHeNyMescaTOKodLC67hTN
2UKwqjVA4Q+LWBRPpxNoqeWOKDPOJcVSkPpKnBf9lP7iPdBI0s2gCuBwkRbggQqY
HZrio/3MtLzkjo65NKRm9/BrexZpIVIIklYgY78mZYij8WF3XfZ0B4FyjoOn7X4A
x9JARSvOkDzlnNZaRz4WSuXDYgfOpsPwo6YdHejEltf1QOY+DV6rlPoQ0szmCzH5
5Xcufi9/33hvMY0sJ4YWUAvBkGmyw2vHotZCzwIDAQABAoIBAAjOuLOACVKCmQ+E
sryx4dNMrIYsYb3AO8tSkAnB/TuvuHKRtgsfzRtncryYSuwXixQFwLne3v7nO4tM
rLm0YTGsfXfLAwRwv28AjcfmGTNJ1rESzedAZ8C/yGhUgCjlN9mkF7Lr5s0NYcxz
pdQKx8xVUuwcecdblXzzMkfXNTe0uEJP1rTzUy5CKNLaY3rj9L+4pefj1zKRZbJK
z/Om1JdvQ3sev2AcaiY5GOVCq+q/mJpQznhCY/0GZvy1eiJ4jBJXTlI3Ifa3m9Oc
q7qH9G9O0+78wVzU9HZbIMnlxrikyWl23ZXB+NxIlDvArk/d4VCZeNkSrtO7zC0/
45sP96ECgYEA7MkboWnzj+CHGfM/7auHNUl9nMMLy07zfIQInu1SMWgaV+9IM3XU
EFmL77vsUuM7o7vU2FFmyFONQ2dB9CRO1OM8gF2dm0Ckc09OpnC0eMt/z7R7RWbg
d5zx70aZJfeePe8Omj8b8iJ6c/WrhmK5hCOIjk5TApQNkNk1oi4kavUCgYEAwNkm
5Jote8aFpMCZ5G6fwGJWwpHJzOqWFmi3rDfwnIeFkJFKDTXzwAtv90r736LGpMtW
0k569Fna+5ENY2SyrBWUC4Ww4l4FLEDzmgFJsau0VE42r7ng9zm2iKUyWg03/Lze
JgIotvViGS1yPoUUv95uEcXznJ58apz+s57QpDMCgYEArRs5gAAdeAoFuwsCqZbE
+kgH9RsC/Fdz2owMYWPOuyAIYlEkz7pMlsdgbptMYiyN5V3kdWDNa5bpp2VN6lbA
6xJVoOLP3jicAVDxhuzOg6ECh67CkDJt2AR9Oxi5zfABV/X1Dv8kRxi9vRjVlSGH
zvrLUn4gYborUMH7W92v8iECgYEApXYrnpyCRd7RL8howcwAmSpG0m4PvRfRaqyy
WrssYMEOYjmmVati1fV6Pa1CamDZGu+0MIFRkXG/J3UPDaaKfoeNHE26tJ6CxbN8
zzgnqJ9v+52X4jITyUrlSFyk1QrebKUH3Yigsknbv0p06Rt58B3CRtGW8Vwx16+Y
ATlUPm0CgYEAtKPvy6+5eCRigT29ejsO9l7hOwrNhxyWJYqUg7RrajQ/SxbPMm6O
hWuV/5Bb4gGpe7lX18nu4dCsNaxlZj4orfeOw7FslZLoV54krgk7PB6sWnlcSyl0
Hua6v6HMIZ66bmHqc7564uyiEWDFXFN+1k/8RNGPRF0spD4J7/gIx90=
-----END RSA PRIVATE KEY-----`)

	jwePrivKeyDer = []byte(b64Dec(`MIIEpQIBAAKCAQEAsl+vKscbGU8TeGLoYJAt+i9zudJtBisoeB4C35EqiRgPXslN6Qu6AP5FTcR4    mBYVzM1txmBELMtZHrZFfRTMRCr3y4JHeNyMescaTOKodLC67hTN2UKwqjVA4Q+LWBRPpxNoqeWO    KDPOJcVSkPpKnBf9lP7iPdBI0s2gCuBwkRbggQqYHZrio/3MtLzkjo65NKRm9/BrexZpIVIIklYg
    Y78mZYij8WF3XfZ0B4FyjoOn7X4Ax9JARSvOkDzlnNZaRz4WSuXDYgfOpsPwo6YdHejEltf1QOY+
    DV6rlPoQ0szmCzH55Xcufi9/33hvMY0sJ4YWUAvBkGmyw2vHotZCzwIDAQABAoIBAAjOuLOACVKC
    mQ+Esryx4dNMrIYsYb3AO8tSkAnB/TuvuHKRtgsfzRtncryYSuwXixQFwLne3v7nO4tMrLm0YTGs
    fXfLAwRwv28AjcfmGTNJ1rESzedAZ8C/yGhUgCjlN9mkF7Lr5s0NYcxzpdQKx8xVUuwcecdblXzz
    MkfXNTe0uEJP1rTzUy5CKNLaY3rj9L+4pefj1zKRZbJKz/Om1JdvQ3sev2AcaiY5GOVCq+q/mJpQ
    znhCY/0GZvy1eiJ4jBJXTlI3Ifa3m9Ocq7qH9G9O0+78wVzU9HZbIMnlxrikyWl23ZXB+NxIlDvA
    rk/d4VCZeNkSrtO7zC0/45sP96ECgYEA7MkboWnzj+CHGfM/7auHNUl9nMMLy07zfIQInu1SMWga
    V+9IM3XUEFmL77vsUuM7o7vU2FFmyFONQ2dB9CRO1OM8gF2dm0Ckc09OpnC0eMt/z7R7RWbgd5zx
    70aZJfeePe8Omj8b8iJ6c/WrhmK5hCOIjk5TApQNkNk1oi4kavUCgYEAwNkm5Jote8aFpMCZ5G6f
    wGJWwpHJzOqWFmi3rDfwnIeFkJFKDTXzwAtv90r736LGpMtW0k569Fna+5ENY2SyrBWUC4Ww4l4F
    LEDzmgFJsau0VE42r7ng9zm2iKUyWg03/LzeJgIotvViGS1yPoUUv95uEcXznJ58apz+s57QpDMC
    gYEArRs5gAAdeAoFuwsCqZbE+kgH9RsC/Fdz2owMYWPOuyAIYlEkz7pMlsdgbptMYiyN5V3kdWDN
    a5bpp2VN6lbA6xJVoOLP3jicAVDxhuzOg6ECh67CkDJt2AR9Oxi5zfABV/X1Dv8kRxi9vRjVlSGH
    zvrLUn4gYborUMH7W92v8iECgYEApXYrnpyCRd7RL8howcwAmSpG0m4PvRfRaqyyWrssYMEOYjmm
    Vati1fV6Pa1CamDZGu+0MIFRkXG/J3UPDaaKfoeNHE26tJ6CxbN8zzgnqJ9v+52X4jITyUrlSFyk
    1QrebKUH3Yigsknbv0p06Rt58B3CRtGW8Vwx16+YATlUPm0CgYEAtKPvy6+5eCRigT29ejsO9l7h
    OwrNhxyWJYqUg7RrajQ/SxbPMm6OhWuV/5Bb4gGpe7lX18nu4dCsNaxlZj4orfeOw7FslZLoV54k
    rgk7PB6sWnlcSyl0Hua6v6HMIZ66bmHqc7564uyiEWDFXFN+1k/8RNGPRF0spD4J7/gIx90=`))

	jwePubKeyPem = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsl+vKscbGU8TeGLoYJAt
+i9zudJtBisoeB4C35EqiRgPXslN6Qu6AP5FTcR4mBYVzM1txmBELMtZHrZFfRTM
RCr3y4JHeNyMescaTOKodLC67hTN2UKwqjVA4Q+LWBRPpxNoqeWOKDPOJcVSkPpK
nBf9lP7iPdBI0s2gCuBwkRbggQqYHZrio/3MtLzkjo65NKRm9/BrexZpIVIIklYg
Y78mZYij8WF3XfZ0B4FyjoOn7X4Ax9JARSvOkDzlnNZaRz4WSuXDYgfOpsPwo6Yd
HejEltf1QOY+DV6rlPoQ0szmCzH55Xcufi9/33hvMY0sJ4YWUAvBkGmyw2vHotZC
zwIDAQAB
-----END PUBLIC KEY-----`)

	jwePubKeyDer = []byte(b64Dec(`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsl+vKscbGU8TeGLoYJAt+i9zudJtBiso
    eB4C35EqiRgPXslN6Qu6AP5FTcR4mBYVzM1txmBELMtZHrZFfRTMRCr3y4JHeNyMescaTOKodLC6
    7hTN2UKwqjVA4Q+LWBRPpxNoqeWOKDPOJcVSkPpKnBf9lP7iPdBI0s2gCuBwkRbggQqYHZrio/3M
    tLzkjo65NKRm9/BrexZpIVIIklYgY78mZYij8WF3XfZ0B4FyjoOn7X4Ax9JARSvOkDzlnNZaRz4W
    SuXDYgfOpsPwo6YdHejEltf1QOY+DV6rlPoQ0szmCzH55Xcufi9/33hvMY0sJ4YWUAvBkGmyw2vH
    otZCzwIDAQAB`))

	jwePrivKey2Pem = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA515unjMo31umXoIjTsKqNyrKYv3DVrNQQqzCHDnVYuhxrU81
6Gj/sW03DBoqYf4Ic7ohbcJFiCzgLU4tYeOT7GZpBZT1UIulHUCg1m/pM3zEpD1U
VRmerfLBuuK4osAF/f1uYddFT/2/p9BiHCxExGcd8bN+Qe2hh7Uz/Tw0tUFNtRFh
lc/MipQhzwHXSr8y1mW5YDNh5Zk4Uz+fyUEnRPLS+MQXn82IrId+gUbV+2uptHyj
lrLpwcxYmk8aB1EQXJevBcFhWI95bIfsm117Y7Oy4OLR/3LBXN5nN0CZfAhOBwBR
vYaJ0RRNFWI/AXHjd32Ron8j16lIDKdS9I9qlwIDAQABAoIBACpthLd6Bjq/Ycje
8H6W8APh0u9IPbP+ee9gItBuQpU6ru3rIqWV652ru3Z6rd7+aKpgLZUlFP8dy5ZD
ScszooKtXQDrCflVQlgU6+mm6ArLDHxZysc4RYL8i04sGVOvBupGuSE0Cr/adnTd
n8Au1gV2K2WRVsvcOczbC8eabMf38mvtsAYn6/Ehfd63IZ0JjurCblK6d477E8V9
iu0XiOLHE9sFHMGkWg2K1QozZDXjVjRMdInVcbc/NZGMgpAj1LHHgUZkr5yWqOMl
IP5R0R8z/6LH/QeXtEQYqORr5K4ONEelH0HYonHCdHjtz12fkErFyAX8mh/25zoV
TJn0JoECgYEA+0bxA8vpX1dmtylRj3GlBEnQFWjTOwCwh5lckcmG8NKBtG752nuz
xSD5fCIsKqzsZAyoItCZ3QtA0K+ryWkYl/gL2DYSPt/rvyw8mEhvBQTbFbfBR9Sy
PeyOjIWcqADvu99w4JcngjB+lR50PWrfkIbwdybzWViMbI/2LZ2fW3cCgYEA67ey
9qaVZN61TE9E1FkvDuN3KA2DH2ho/mvlWKsF9ft+6LqXlsLbhxgVFxjX0RFqGLeq
DYb1/0dKHknEq6V0ZQRNZ1JuzeuTduZ8vuKdBI6JkWK86oAykGTq0nLTw0IINE3J
qSbifugYgRAPL/6hXVPbTh9BUam8duxthUwD8eECgYEAmLt/JbqdCGmcsno37AO8
tMWU6F6F/hgmNNXAEZE4J0scsaq+zdFg7NJlMtGmnO3s5cdXr4mx7Ey5wd71gQAT
hdOsh2geYP9EUTg3QKzOZnOUIzhFED81dDREVR+ln+ypyz0+ZBUcW6LUXhlbuDUs
3LFYmmQfiFAtUpOSpBlp0nMCgYEA0nGI12hWDF5AokZK/wI4XyR5J0sY+5tt0Wdm
tMjLY5cK8KBV4gVJlMzNV3eYhlDz1elzauxJB4YQCAZ4DX6D8gPrTwlrX3CokQip
6onLAVx4OVJbs0iM3BkdBJH7uWFkjb29AsVyhTaVWfSKeqDsU7QgIRkKaewOFGZ0
SQNaqkECgYEA94y65SrkydMBcqlZ1+qxNJcFlLTZ7abkuZb7C/Tyb9gRVzlLujfD
ZZ5a0Bv28a5z1iUa9TDu7gc+3hBq4quE2i8BZhAEVYsrD4HhhEeu2qpk8u5M05il
4WAAWmgaMLm6abjz2sbcvVb9GAaM/M5ZE6G4cetNQhrGJBa3FS12zlI=
-----END RSA PRIVATE KEY-----`)

	jwePubKey2Pem = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA515unjMo31umXoIjTsKq
NyrKYv3DVrNQQqzCHDnVYuhxrU816Gj/sW03DBoqYf4Ic7ohbcJFiCzgLU4tYeOT
7GZpBZT1UIulHUCg1m/pM3zEpD1UVRmerfLBuuK4osAF/f1uYddFT/2/p9BiHCxE
xGcd8bN+Qe2hh7Uz/Tw0tUFNtRFhlc/MipQhzwHXSr8y1mW5YDNh5Zk4Uz+fyUEn
RPLS+MQXn82IrId+gUbV+2uptHyjlrLpwcxYmk8aB1EQXJevBcFhWI95bIfsm117
Y7Oy4OLR/3LBXN5nN0CZfAhOBwBRvYaJ0RRNFWI/AXHjd32Ron8j16lIDKdS9I9q
lwIDAQAB
-----END PUBLIC KEY-----`)

	jwePrivKeyJwk = []byte(`{"d":"pGBXnqbPbMR6PIPkyzz1OhmJq4ORmlHwh2GunXJuzSj1AhYL9rZ8fd_NNn128yPmllTN6LOBqNj1vqXOnMaeu63vdn08z8xTDlCsuUt2T0NzgQlPuducu8K0OURFqf-C3dIPqipxnWKydN7_gYEEYosxgKU3B8WolA65YFTaUxv-NQL-3rASUTtiQ1rtm2l-RBEIqOuFh350Bahnq_gtINxKpVahpLDiLTte6HpnbzU7ei_dW4v3j6foMg2pOWUAcfxNfmZwQO-eEge88E5WfN7HIQnBTTjAjrNwIP-SfaDmKpa37at1kTG932If0VopQ9CJZE_jM2wHx3VfZiTmAQ","dp":"RFUZdzAaCs3ak4lxptnHy5J_ujWgHk1CvzyIU1tEw1P9BCme-pW30YdEvXkXMzqiX8g0p6WdEvbfx0I9dctje9IbjCQcemxjIUx-2ifUppp8_I4BCaZ4K4puyt65TJL2za6PmyuVTDlugYceMIupmZ4bx6C70bjTeo1ErVe-yYE","dq":"zOCBbLcqCtkXUQqlmOEmb35GBc5HLV6LcQSYAm1mhMIRjK-cSiXAlg4yKhXoGNAuU-LBXyVLeOa4cNdG_v-34XZGmqIyBWG1ehmMumcblzI2-Cuj76jW26sWBvPBH7cyEf1FULS3acF-xPd8TkNA9P0laZmCshOfa_-zkMM5Tf8","e":"AQAB","kty":"RSA","n":"zMwIcZn24y3Aj-P5Vox-w54FkpoRGeYGhyF7rdDQN2bYO-8h09doVbbgstYauyZKRvk3iWoOwfY9foD0hHCJNtT20sqbx40osGN9qLERweO6Xn8adhVPN7isTT9KozdvsrOIBr7uQUsruvow4klIYrv5FqS_RHpy4f0CUlsjPqc3F5PC4yV0D0f_QUApr06--uHRdH3ucunvdwR1V1IZV0DEJwZ5DzEDQmynzo5oV1UVNb9DSzTXsUAzSipCrdIyUxCnofPp_PzKvqMbctBAchx0AKN8IK8Z3RGFYyrV3HxkXqFxZ4aTVnkXqlnGV5CRQhx59ckIWUxAlyLcGLXvmw","p":"_aCnqjENQBE-he_7XWBo7kXJHnOz6SucuLNPo35imTO4nJBkga9HOF8VxeM3OrskEFVudkDvSqbq4KtERiCGL8f3-LAUKSFaxULa0h9FPJOlks_JXVlDwGsXOyHirIHIEvvbjAAQlV_F7tQNCzSHuXmegh3yJWLwz6EcUw2z9YE","q":"zrZyXsm2jVHc9JkWEp8CMJ0J65f87KrYjQgcb46XkCK1E7bnFDLiNzYV-CQ8a9kKuWfd_LUx2FIjwrik5IFQXJA7Z7s4jvAh2J-pLutSD4sU0KAXcH8W85jLd9C0varGXWFFD7axv-FjDEEQ8TL35Nh5svILn_hgMfB2TPNuixs","qi":"GgGk6GPOtfo2TFtuPQPVTTPGmEzoVekZNH9VQfvQchiRyU1cddYWGRzzJct1zP0GhRsam7m27zguxxVVOORjM5NAPHhjhuwmncmi5hZDyfyIURPXOgslPNG42XdIZdfJtgxqUuOhLNfeQcQXJM8S2EpauLmlm14blP5V-7ZOXO0"}`)

	jwePubKeyJwk = []byte(`{"e":"AQAB","kty":"RSA","n":"zMwIcZn24y3Aj-P5Vox-w54FkpoRGeYGhyF7rdDQN2bYO-8h09doVbbgstYauyZKRvk3iWoOwfY9foD0hHCJNtT20sqbx40osGN9qLERweO6Xn8adhVPN7isTT9KozdvsrOIBr7uQUsruvow4klIYrv5FqS_RHpy4f0CUlsjPqc3F5PC4yV0D0f_QUApr06--uHRdH3ucunvdwR1V1IZV0DEJwZ5DzEDQmynzo5oV1UVNb9DSzTXsUAzSipCrdIyUxCnofPp_PzKvqMbctBAchx0AKN8IK8Z3RGFYyrV3HxkXqFxZ4aTVnkXqlnGV5CRQhx59ckIWUxAlyLcGLXvmw"}`)

	jwePrivKey3PassPem = []byte(`-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,EAFCC41954E0B6C1721C04F6F45C453F

LF075JLEupR95dRrCaoUqKp2+8+9K12AqMfgJwHoC1HXHV1bMxRLaMPWfQWKrUIV
zsdhQ6lYZcAOMRLl6NpADLIL32t+56/5DFpKbI6otb5EBWq9SM4S77dq66VPPGPx
r1g3XqkBEnawApjBMccaFH51wFlUoadXajBGfVJy2JLUXg+bEe4g2umTewpm+F8v
HPx1c0UZYcQWeY1nLJiJYFHTvdK/xOglfypnTIrIRN+Ku3TIeeY0Cc+OA2tona+l
IFvwHfLslSA712YHtJOjpXRMX6N4v/oW95ZT3f7zQM4IAlbWFY17dsBMjtM9qZof
UIEF2FB9j/tkC5Co0DCJ82YEEm/8GnOCHWOAdia6IHmjw6JWwA6hmd3AoKgrs4K4
hqY5GDNCgXhfZEt5V7od6vYZOhi2k+qUBE5TYNDE7rdjjmTu+o62SI/aWo1QAZM1
RHu+TkLt4EfpIbO/VmVQqb8/BGwZs+OgSwe5bDTuDoTyU2037gmyIwgAA+pASG/j
Or/COu3hKBsV+Afluh+q7kVBbYt3B05/eGMqvr0LgoyZlCRICbuTilE5VxRIN1Xv
8YYqfl5w5OFJ8IUX13VwT8wDwGdxoH8Z8En2PhvdM96+mz5ZurPpyUavNe03tub0
I+kbFps+2sQg8a/R7gREJZ3OBj8+LFcjHJYwl4pa38jwijC1EpsxhXCA4meg5iFr
R8jorTmvrdLPG+yVXnFIUQrEzjnLVd/EEaDe9wQ0Ez6xaum68bHc2zgwb89ylJGr
dmbfid7qAjqt/AMdxM45+RugYyBUTXauJVa/L8EGl4qO15BHXDEftRvj7mvibEAz
tzuEZlu5vsRssuTm3k47adHWw0NgUPo1Yf0gsMP2QDMFRVTfxOte1nta2Che3wdD
cLUL9cLAXsi7YYYliBhmWac2t6TL7hF+65JpV2YwI33JlCZNaA8aCDx6Jtck0xTR
NwWjRiXdxuroLJWGDzLVXkRm6olxI9V2bQGNHwseO+mdNwWYHZHqela0bJSBqEDK
sCqsgr0XtEHJvijA6VvL019RnJdAhXmfs0zQSEi6m++WJeglcAGpX1xRYWBdEvVU
Gj48LHYQkctY9H5w3+SFcTWwpzT3S7PmCbz5kmCMGWjzgk1EIkLR9rxRJRKJQBCn
6eQWy3JVqe9qEiHZEskdlJuwAsDc4d1C1X+2grrKZhnrDzPs2oWwnNMi18JJabb2
OXkEWXXOnpE5nOZFCF2JgaPSKLdp8SbB3qVhqL0lD2yYn3p7U+hrpTCg4flv1uW3
72iLgpjF3joVZNUMnS+e8TQVULYKg4jqkPuML0p+Ja349X2EI3+oekwHJfdaZuHa
iDzLjBVbgpJoIuexg/6o51+rEvEheWWF6jprktBkeEyPRuNCWwJ43dqiNdWKEJtg
rFPHc7G+k42RQedMaZ9BG0QL1KhIXPKhhqatNmRf9kt3LWgbXxOvfHFfOASDrVpP
3Xp++hZBCPxBz5tcnL+6Fmu9xbSBlRjRhxQUvrAGWREKNHn4AmzcWo0QHSZ9AGpo
uCAdX11A0nhKBqp4OSeWcS1+o+8YSnxAfcfxc1c/XK0c9x69BcPzD9vTJfI45gVr
-----END RSA PRIVATE KEY-----`)

	jwePrivKey3Password = []byte("password")

	jwePubKey3Pem = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuth6hClB1aqsZV6z4+kp
+SUQWyCEHM70Gz/MII70gteDmDB3c/M+5k13bNCYhl1yG2b3FDphaDug2QRYN7dG
qpUgrmyP7jgD3NdbSkKNqLAZVpVh6jBSL8R39zWrT+AmpUXtiiJptsWYZLrc8G85
4FQMfltJOzwj5gAff6s+cnJ+cMfuFOSUDDR1cDlbhmYyULivXmPzqKHwTu0jnbI3
+K7xRH0+a5cxi6KXRb21WHY/z58D4yRIr0WTS/DTLmo5O8ii+VkiwYg8bnREv0YT
EYHEiiFA3e48J1U0aHTon4ZrKbw8FgBzUaX73LMz4lcF3ZUKeSSZU0D6guguTUG+
KQIDAQAB
-----END PUBLIC KEY-----
`)

	jweEcPrivKeyDer = []byte(b64Dec(`MIHcAgEBBEIBDE7CxDqkRxo2Nfl9bahrEwRKMHTVRiGNiZVkakEN63A8CpR/vNEXJ8VpvgnZo6bU
SnOYjiyWqC93NPhDD6Z0CxqgBwYFK4EEACOhgYkDgYYABACwgwNmTNs6x2T+yQDkvlIqU16L4uzV
gL+/d68a7g5vGVLnyaaijN+kG9en6EBSOAxtkXYHeTjGPZYMivaYUU7AwAA9lZ6sAqFj9YrxOtF4
gN2FC66feQhUktZzskgETrB0TJjiy77CwJqEMYXM14205K4+SqhuYYPb3xREAec43wCxXA==
`))

	jweEcPubKeyPem = []byte(`-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAsIMDZkzbOsdk/skA5L5SKlNei+Ls
1YC/v3evGu4ObxlS58mmoozfpBvXp+hAUjgMbZF2B3k4xj2WDIr2mFFOwMAAPZWe
rAKhY/WK8TrReIDdhQuun3kIVJLWc7JIBE6wdEyY4su+wsCahDGFzNeNtOSuPkqo
bmGD298URAHnON8AsVw=
-----END PUBLIC KEY-----
`)
)
