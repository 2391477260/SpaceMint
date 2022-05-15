package pos

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"testing"
	"time"
	// "reflect"
)

//exp* gets setup in test.go
var prover *Prover = nil
var verifier *Verifier = nil
var pk []byte
var index int64 = 2048
var size int = 1           // parameter dat de size van de to be initialized file aanpast
var beta int = 30          // aantal nodes
var graphDir string = "Xi" // direction naam hier
var name string = "G"

func TestPoS(t *testing.T) {
	seed := make([]byte, 64)
	rand.Read(seed)
	challenges := verifier.SelectChallenges(seed) // sloot aan challenges voor verificatie stap

	// // extra challenge info
	// xt := reflect.TypeOf(challenges).Kind()
	// fmt.Println("Number of challenges:", len(challenges))
	// fmt.Printf("%T: %s\n", xt, xt)

	now := time.Now()
	hashes, parents, proofs, pProofs := prover.ProveSpace(challenges)
	// fmt.Printf("hashes: %T, %d\n", hashes, unsafe.Sizeof(hashes))
	// fmt.Printf("parents: %T, %d\n", parents, unsafe.Sizeof(parents))
	// fmt.Printf("proofs: %T, %d\n", proofs, unsafe.Sizeof(proofs))
	// fmt.Printf("pProofs: %T, %d\n", pProofs, unsafe.Sizeof(pProofs))

	fmt.Printf("Prove: %f\n", time.Since(now).Seconds())
	now = time.Now()
	if !verifier.VerifySpace(challenges, hashes, parents, proofs, pProofs) {
		log.Fatal("Verify space failed:", challenges)
	}
	fmt.Printf("Verify: %f\n", time.Since(now).Seconds())
}

func TestMain(m *testing.M) {
	// size = numXi(index)
	pk = []byte{1}

	runtime.GOMAXPROCS(runtime.NumCPU())

	id := flag.Int("index", size, "graph index")
	flag.Parse()
	index = int64(*id)

	graphDir = fmt.Sprintf("%s%d", graphDir, *id)
	os.RemoveAll(graphDir)

	now := time.Now()
	prover = NewProver(pk, index, name, graphDir)
	fmt.Printf("%d. Graph gen: %f\n", index, time.Since(now).Seconds())

	now = time.Now()
	commit := prover.Init()
	fmt.Printf("%d. Graph commit: %f\n", index, time.Since(now).Seconds())

	root := commit.Commit
	verifier = NewVerifier(pk, index, beta, root)

	os.Exit(m.Run())
}
