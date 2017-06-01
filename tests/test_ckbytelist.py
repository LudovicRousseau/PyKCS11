import unittest
import PyKCS11


class Testutil(unittest.TestCase):

    def test_empty(self):
        ck = PyKCS11.ckbytelist()
        self.assertSequenceEqual(ck, [])

    def test_data(self):
        size = 5
        ck = PyKCS11.ckbytelist(size)
        for index in range(size):
            ck[index] = index
        self.assertSequenceEqual(ck, range(size))

    def test_length(self):
        size = 5
        ck = PyKCS11.ckbytelist(size)
        self.assertEqual(len(ck), size)

    def test_string(self):
        size = 5
        ck = PyKCS11.ckbytelist(size)
        for index in range(size):
            ck[index] = index
        self.assertEqual(str(ck), str(list(range(size))))


if __name__ == '__main__':
    unittest.main()
