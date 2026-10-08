import SwiftUI
import AVFoundation
import Network
import BackgroundTasks
import Bind

@main
struct FastimeApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) var delegate

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 48))
            Text("Fastime 运行中")
                .font(.headline)
            Text("本地加密中继已在后台保活")
                .font(.footnote)
                .foregroundColor(.secondary)
        }
    }
}

class AppDelegate: NSObject, UIApplicationDelegate {
    private var player: AVAudioPlayer?
    private var pathMonitor: NWPathMonitor?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        // 1. 启动 Go 中继核心（配置已在构建期注入）
        var err: NSError?
        BindStart(&err)
        if let err = err { NSLog("BindStart error: \(err)") }

        // 2. 静音音频循环保活（audio 后台模式）
        startSilentAudioLoop()

        // 3. NWPathMonitor：系统级网络切换回调，比 Go 侧 2s 轮询更快
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { _ in BindOnNetworkChanged() }
        monitor.start(queue: DispatchQueue.global())
        pathMonitor = monitor

        // 4. 注册后台任务，系统调度时唤醒续命
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: "com.fastime.refresh", using: nil
        ) { task in
            BindOnNetworkChanged()
            task.setTaskCompleted(success: true)
        }
        return true
    }

    /// 运行时生成 1 秒静音 WAV，循环播放。AVAudioSession 设为 playback
    /// 并激活后，iOS 会持续给进程分配后台执行时间。
    private func startSilentAudioLoop() {
        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.playback, options: .mixWithOthers)
            try session.setActive(true)

            let sampleRate = 8000
            let frames = [UInt8](repeating: 0x80, count: sampleRate) // 1s 8bit PCM 静音
            var data = Data()
            let dataSize = UInt32(frames.count)
            // 手工拼一个最小 WAV 头
            data.append(contentsOf: "RIFF".utf8)
            data.append(contentsOf: withUnsafeBytes(of: UInt32(36 + dataSize).littleEndian, Array.init))
            data.append(contentsOf: "WAVEfmt ".utf8)
            data.append(contentsOf: withUnsafeBytes(of: UInt32(16).littleEndian, Array.init))
            data.append(contentsOf: withUnsafeBytes(of: UInt16(1).littleEndian, Array.init))  // PCM
            data.append(contentsOf: withUnsafeBytes(of: UInt16(1).littleEndian, Array.init))  // mono
            data.append(contentsOf: withUnsafeBytes(of: UInt32(sampleRate).littleEndian, Array.init))
            data.append(contentsOf: withUnsafeBytes(of: UInt32(sampleRate).littleEndian, Array.init))
            data.append(contentsOf: withUnsafeBytes(of: UInt16(1).littleEndian, Array.init))
            data.append(contentsOf: withUnsafeBytes(of: UInt16(8).littleEndian, Array.init))  // 8bit
            data.append(contentsOf: "data".utf8)
            data.append(contentsOf: withUnsafeBytes(of: dataSize.littleEndian, Array.init))
            data.append(contentsOf: frames)

            let p = try AVAudioPlayer(data: data)
            p.numberOfLoops = -1
            p.volume = 0.01 // 双保险：即便发声也几乎听不见
            p.prepareToPlay()
            p.play()
            player = p
        } catch {
            NSLog("silent audio failed: \(error)")
        }
    }
}
